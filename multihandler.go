// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"fmt"
	"net"
	"sync"
)

// MultiPacketResult extends PacketResult with the handler that processed the packet.
type MultiPacketResult struct {
	*PacketResult
	Handler *Handler // which identity processed the packet
}

// MultiHandler multiplexes multiple Handler instances on a single UDP port.
// It routes incoming packets to the correct handler based on MAC1 (for
// initiation messages), pending handshake index (for responses and cookie
// replies), or keypair index (for transport data).
type MultiHandler struct {
	mu       sync.RWMutex
	handlers []*Handler
}

// NewMultiHandler creates a MultiHandler from one or more handlers.
// Returns an error if no handlers are provided or if duplicate public keys are detected.
func NewMultiHandler(handlers ...*Handler) (*MultiHandler, error) {
	if len(handlers) == 0 {
		return nil, fmt.Errorf("at least one handler is required")
	}

	seen := make(map[NoisePublicKey]struct{}, len(handlers))
	for _, h := range handlers {
		pk := h.PublicKey()
		if _, dup := seen[pk]; dup {
			return nil, fmt.Errorf("duplicate public key")
		}
		seen[pk] = struct{}{}
	}

	mh := &MultiHandler{
		handlers: make([]*Handler, len(handlers)),
	}
	copy(mh.handlers, handlers)
	return mh, nil
}

// AddHandler adds a handler to the MultiHandler.
// Returns an error if a handler with the same public key already exists.
func (mh *MultiHandler) AddHandler(h *Handler) error {
	pk := h.PublicKey()

	mh.mu.Lock()
	defer mh.mu.Unlock()

	for _, existing := range mh.handlers {
		if existing.PublicKey() == pk {
			return fmt.Errorf("handler with this public key already exists")
		}
	}

	mh.handlers = append(mh.handlers, h)
	return nil
}

// RemoveHandler removes and returns the handler with the given public key.
// Returns nil if no handler matches.
func (mh *MultiHandler) RemoveHandler(pubKey NoisePublicKey) *Handler {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	for i, h := range mh.handlers {
		if h.PublicKey() == pubKey {
			mh.handlers = append(mh.handlers[:i], mh.handlers[i+1:]...)
			return h
		}
	}
	return nil
}

// Handlers returns a snapshot of all handlers.
func (mh *MultiHandler) Handlers() []*Handler {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	out := make([]*Handler, len(mh.handlers))
	copy(out, mh.handlers)
	return out
}

// Handler returns the handler with the given public key, or nil if not found.
func (mh *MultiHandler) Handler(pubKey NoisePublicKey) *Handler {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	for _, h := range mh.handlers {
		if h.PublicKey() == pubKey {
			return h
		}
	}
	return nil
}

// ProcessPacket routes an incoming packet to the correct handler and processes it.
//
// For handshake initiation (type 1): iterates handlers and checks MAC1 against each.
// For handshake response (type 2) and cookie reply (type 3): extracts the receiver
// index and checks pending handshake ownership.
// For transport data (type 4): extracts the receiver index and checks keypair ownership.
// Other message types return an error.
func (mh *MultiHandler) ProcessPacket(data []byte, remoteAddr *net.UDPAddr) (*MultiPacketResult, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	msgType := binary_le_uint32(data[0:4])

	switch msgType {
	case MessageInitiationType:
		return mh.routeHandshake(data, remoteAddr)
	case MessageResponseType, MessageCookieReplyType:
		return mh.routeByReceiverIndex(data, remoteAddr)
	case MessageTransportType:
		return mh.routeTransport(data, remoteAddr)
	default:
		return nil, fmt.Errorf("unsupported message type for MultiHandler: %d", msgType)
	}
}

// routeHandshake routes a type-1 initiation by finding the handler whose MAC1 matches.
func (mh *MultiHandler) routeHandshake(data []byte, remoteAddr *net.UDPAddr) (*MultiPacketResult, error) {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	for _, h := range mh.handlers {
		if h.cookieChecker.CheckMAC1(data) {
			result, err := h.ProcessPacket(data, remoteAddr)
			if err != nil {
				return nil, err
			}
			return &MultiPacketResult{PacketResult: result, Handler: h}, nil
		}
	}

	return nil, fmt.Errorf("no handler matched MAC1 for handshake initiation")
}

// routeTransport routes a type-4 transport packet by finding the handler that owns
// the keypair for the receiver index.
func (mh *MultiHandler) routeTransport(data []byte, remoteAddr *net.UDPAddr) (*MultiPacketResult, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("transport packet too short: %d bytes", len(data))
	}

	receiverIdx := binary_le_uint32(data[4:8])

	mh.mu.RLock()
	defer mh.mu.RUnlock()

	for _, h := range mh.handlers {
		if h.hasKeypairIndex(receiverIdx) {
			result, err := h.ProcessPacket(data, remoteAddr)
			if err != nil {
				return nil, err
			}
			return &MultiPacketResult{PacketResult: result, Handler: h}, nil
		}
	}

	return nil, fmt.Errorf("no handler owns receiver index %d", receiverIdx)
}

// routeByReceiverIndex routes type-2 (response) and type-3 (cookie reply) messages
// by checking which handler has a pending handshake matching the receiver index.
func (mh *MultiHandler) routeByReceiverIndex(data []byte, remoteAddr *net.UDPAddr) (*MultiPacketResult, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short for receiver index: %d bytes", len(data))
	}

	receiverIdx := binary_le_uint32(data[4:8])

	mh.mu.RLock()
	defer mh.mu.RUnlock()

	for _, h := range mh.handlers {
		if h.hasHandshakeIndex(receiverIdx) {
			result, err := h.ProcessPacket(data, remoteAddr)
			if err != nil {
				return nil, err
			}
			// result may be nil (cookie reply returns nil)
			if result == nil {
				return nil, nil
			}
			return &MultiPacketResult{PacketResult: result, Handler: h}, nil
		}
	}

	return nil, fmt.Errorf("no handler has pending handshake for receiver index %d", receiverIdx)
}

// Maintenance calls Maintenance on all handlers.
func (mh *MultiHandler) Maintenance() {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	for _, h := range mh.handlers {
		h.Maintenance()
	}
}

// Close closes all handlers, returning the first error encountered.
func (mh *MultiHandler) Close() error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	var firstErr error
	for _, h := range mh.handlers {
		if err := h.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
