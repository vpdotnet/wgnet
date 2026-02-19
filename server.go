// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ServerConfig configures a Server.
type ServerConfig struct {
	// Handler provides a single WireGuard identity.
	// Mutually exclusive with MultiHandler.
	Handler *Handler

	// MultiHandler provides multiple WireGuard identities.
	// Mutually exclusive with Handler.
	MultiHandler *MultiHandler

	// OnPacket is called when decrypted transport data arrives. The handler
	// argument identifies which identity processed the packet (always the
	// same pointer in single-handler mode).
	OnPacket func(data []byte, peerKey NoisePublicKey, handler *Handler)

	// OnPeerConnected is called when a new handshake completes. Optional.
	OnPeerConnected func(peerKey NoisePublicKey, handler *Handler)

	// MaintenanceInterval controls how often handler maintenance runs.
	// Default: 10s.
	MaintenanceInterval time.Duration

	// ReadBufferSize is the size of the UDP read buffer. Default: 2048.
	ReadBufferSize int
}

// Server manages a WireGuard endpoint over a net.PacketConn, handling the
// read loop, automatic protocol responses, and periodic maintenance.
type Server struct {
	handler             *Handler
	multiHandler        *MultiHandler
	onPacket            func(data []byte, peerKey NoisePublicKey, handler *Handler)
	onPeerConnected     func(peerKey NoisePublicKey, handler *Handler)
	maintenanceInterval time.Duration
	readBufferSize      int

	conn      net.PacketConn
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	addrsMu   sync.RWMutex
	peerAddrs map[NoisePublicKey]*net.UDPAddr

	handlersMu   sync.RWMutex
	peerHandlers map[NoisePublicKey]*Handler // multi-handler only
}

// NewServer creates a Server from the given configuration.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Handler == nil && cfg.MultiHandler == nil {
		return nil, errors.New("wgnet: either Handler or MultiHandler must be set")
	}
	if cfg.Handler != nil && cfg.MultiHandler != nil {
		return nil, errors.New("wgnet: Handler and MultiHandler are mutually exclusive")
	}
	if cfg.OnPacket == nil {
		return nil, errors.New("wgnet: OnPacket callback is required")
	}

	interval := cfg.MaintenanceInterval
	if interval == 0 {
		interval = 10 * time.Second
	}
	bufSize := cfg.ReadBufferSize
	if bufSize == 0 {
		bufSize = 2048
	}

	s := &Server{
		handler:             cfg.Handler,
		multiHandler:        cfg.MultiHandler,
		onPacket:            cfg.OnPacket,
		onPeerConnected:     cfg.OnPeerConnected,
		maintenanceInterval: interval,
		readBufferSize:      bufSize,
		done:                make(chan struct{}),
		peerAddrs:           make(map[NoisePublicKey]*net.UDPAddr),
	}
	if cfg.MultiHandler != nil {
		s.peerHandlers = make(map[NoisePublicKey]*Handler)
	}
	return s, nil
}

// Serve starts the read loop and maintenance goroutines, blocking until
// Close is called or the connection encounters a permanent error.
func (s *Server) Serve(conn net.PacketConn) error {
	s.conn = conn

	s.wg.Add(2)
	go s.readLoop()
	go s.maintenanceLoop()

	<-s.done
	s.wg.Wait()
	return nil
}

// Send encrypts data and sends it to the given peer. In multi-handler mode
// the handler is chosen automatically based on which handler completed the
// peer's handshake. Use SendTo to specify the handler explicitly.
func (s *Server) Send(data []byte, peerKey NoisePublicKey) error {
	var h *Handler
	if s.multiHandler != nil {
		s.handlersMu.RLock()
		h = s.peerHandlers[peerKey]
		s.handlersMu.RUnlock()
		if h == nil {
			return errors.New("wgnet: no handler found for peer")
		}
	} else {
		h = s.handler
	}
	return s.sendWith(data, peerKey, h)
}

// SendTo encrypts data and sends it to the given peer using the specified
// handler. This is useful in multi-handler mode when you want to select
// the identity explicitly.
func (s *Server) SendTo(data []byte, peerKey NoisePublicKey, handler *Handler) error {
	return s.sendWith(data, peerKey, handler)
}

// PeerAddr returns the last known UDP address for the given peer, or nil
// if the peer has not been seen.
func (s *Server) PeerAddr(peerKey NoisePublicKey) *net.UDPAddr {
	s.addrsMu.RLock()
	defer s.addrsMu.RUnlock()
	return s.peerAddrs[peerKey]
}

// Close stops the server's read loop and maintenance goroutines. It does
// not close the net.PacketConn or the handler(s) -- the caller owns those.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	// Always try to unblock a pending ReadFrom, even if closeOnce already ran.
	if s.conn != nil {
		s.conn.SetReadDeadline(time.Now())
	}
	s.wg.Wait()
	return nil
}

func (s *Server) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, s.readBufferSize)

	for {
		s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Permanent read error -- shut down.
			s.closeOnce.Do(func() {
				close(s.done)
			})
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		s.processIncoming(data, addr)
	}
}

func (s *Server) processIncoming(data []byte, addr net.Addr) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}

	var (
		result  *PacketResult
		handler *Handler
		err     error
	)

	if s.multiHandler != nil {
		mr, e := s.multiHandler.ProcessPacket(data, udpAddr)
		if e != nil {
			return
		}
		if mr == nil {
			return
		}
		result = mr.PacketResult
		handler = mr.Handler
	} else {
		result, err = s.handler.ProcessPacket(data, udpAddr)
		if err != nil {
			return
		}
		handler = s.handler
	}

	if result == nil {
		return
	}

	// Update peer address (skip when PeerKey is zero, e.g. cookie replies).
	var zeroKey NoisePublicKey
	if result.PeerKey != zeroKey {
		addrCopy := *udpAddr
		s.addrsMu.Lock()
		s.peerAddrs[result.PeerKey] = &addrCopy
		s.addrsMu.Unlock()

		if s.peerHandlers != nil {
			s.handlersMu.Lock()
			s.peerHandlers[result.PeerKey] = handler
			s.handlersMu.Unlock()
		}
	}

	switch result.Type {
	case PacketHandshakeResponse, PacketCookieReply:
		s.conn.WriteTo(result.Response, addr)
		if result.Type == PacketHandshakeResponse && s.onPeerConnected != nil {
			s.onPeerConnected(result.PeerKey, handler)
		}
	case PacketTransportData:
		s.onPacket(result.Data, result.PeerKey, handler)
	case PacketKeepalive:
		// Address already updated above.
	}
}

func (s *Server) maintenanceLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.maintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.multiHandler != nil {
				s.multiHandler.Maintenance()
			} else {
				s.handler.Maintenance()
			}
		}
	}
}

// Connect initiates a handshake to a peer at the given address.
// In single-handler mode, uses the handler. In multi-handler mode, returns an error
// (use ConnectWith to specify the handler).
func (s *Server) Connect(peerKey NoisePublicKey, addr *net.UDPAddr) error {
	if s.multiHandler != nil {
		return errors.New("wgnet: use ConnectWith in multi-handler mode")
	}
	return s.connectWith(peerKey, addr, s.handler)
}

// ConnectWith initiates a handshake to a peer using the specified handler.
func (s *Server) ConnectWith(peerKey NoisePublicKey, addr *net.UDPAddr, handler *Handler) error {
	return s.connectWith(peerKey, addr, handler)
}

func (s *Server) connectWith(peerKey NoisePublicKey, addr *net.UDPAddr, handler *Handler) error {
	initPkt, err := handler.InitiateHandshake(peerKey)
	if err != nil {
		return fmt.Errorf("wgnet: initiate handshake: %w", err)
	}

	// Pre-register peer address so the response can be correlated
	addrCopy := *addr
	s.addrsMu.Lock()
	s.peerAddrs[peerKey] = &addrCopy
	s.addrsMu.Unlock()

	if s.peerHandlers != nil {
		s.handlersMu.Lock()
		s.peerHandlers[peerKey] = handler
		s.handlersMu.Unlock()
	}

	_, err = s.conn.WriteTo(initPkt, addr)
	return err
}

func (s *Server) sendWith(data []byte, peerKey NoisePublicKey, handler *Handler) error {
	s.addrsMu.RLock()
	addr := s.peerAddrs[peerKey]
	s.addrsMu.RUnlock()
	if addr == nil {
		return errors.New("wgnet: no address known for peer")
	}

	encrypted, err := handler.Encrypt(data, peerKey)
	if err != nil {
		return err
	}

	_, err = s.conn.WriteTo(encrypted, addr)
	return err
}
