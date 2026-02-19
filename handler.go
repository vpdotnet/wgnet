// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// UnknownPeerFunc is called when a handshake is received from an unknown peer.
// Return true to authorize the peer and proceed with the handshake.
// Return false to silently drop the handshake.
type UnknownPeerFunc func(publicKey NoisePublicKey, remoteAddr *net.UDPAddr) bool

// Config configures a Handler.
type Config struct {
	// PrivateKey is the local static private key. If zero, a new key is generated.
	PrivateKey NoisePrivateKey

	// OnUnknownPeer is called when a handshake arrives from an unauthorized peer.
	// If nil, unknown peers are rejected.
	OnUnknownPeer UnknownPeerFunc
}

// PacketType indicates the type of a processed packet result.
type PacketType int

const (
	// PacketHandshakeResponse indicates a completed handshake with response bytes
	// that should be sent back. On the responder side this is the handshake response
	// message; on the initiator side it is a keepalive confirming the session.
	PacketHandshakeResponse PacketType = iota
	// PacketCookieReply indicates a cookie reply that should be sent back.
	PacketCookieReply
	// PacketTransportData indicates decrypted transport data.
	PacketTransportData
	// PacketKeepalive indicates a keepalive (empty transport data).
	PacketKeepalive
)

// PacketResult is the result of processing an incoming packet.
type PacketResult struct {
	// Type indicates what kind of result this is.
	Type PacketType
	// Response contains bytes to send back to the remote address (handshake or cookie reply).
	Response []byte
	// Data contains decrypted plaintext (transport data).
	Data []byte
	// PeerKey is the public key of the peer.
	PeerKey NoisePublicKey
}

// Handler implements the WireGuard protocol, supporting both initiator and
// responder roles. Use InitiateHandshake to start a connection, or pass
// incoming packets to ProcessPacket to respond to them.
type Handler struct {
	privateKey      NoisePrivateKey
	publicKey       NoisePublicKey
	onUnknownPeer   UnknownPeerFunc
	cookieChecker   CookieChecker
	cookieGenerator CookieGenerator

	// DoS mitigation
	underLoad        bool
	loadMutex        sync.RWMutex
	activeHandshakes int
	handshakeMutex   sync.RWMutex

	// Handshake tracking
	handshakes      map[uint32]*Handshake
	handshakesMutex sync.RWMutex

	// Keypair tracking
	keypairs      map[uint32]*Keypair
	keypairsMutex sync.RWMutex

	// Per-peer send counters
	peerCounters  map[NoisePublicKey]uint64
	countersMutex sync.RWMutex

	// Sessions by peer public key
	sessions      map[NoisePublicKey]*Session
	sessionsMutex sync.RWMutex

	// Peer authorization
	peers      map[NoisePublicKey]*PeerInfo
	peersMutex sync.RWMutex

	// Buffer pools
	packetPool *sync.Pool
}

// PeerInfo contains information about an authorized peer.
type PeerInfo struct {
	PublicKey     NoisePublicKey
	PresharedKey  NoisePresharedKey
	HasPSK        bool
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastHandshake time.Time
	cookieGen     CookieGenerator
}

// NewHandler creates a new WireGuard protocol handler.
func NewHandler(cfg Config) (*Handler, error) {
	privKey := cfg.PrivateKey
	if privKey == (NoisePrivateKey{}) {
		var err error
		privKey, err = GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	pubKey := privKey.PublicKey()

	h := &Handler{
		privateKey:    privKey,
		publicKey:     pubKey,
		onUnknownPeer: cfg.OnUnknownPeer,
		handshakes:    make(map[uint32]*Handshake),
		keypairs:      make(map[uint32]*Keypair),
		sessions:      make(map[NoisePublicKey]*Session),
		peerCounters:  make(map[NoisePublicKey]uint64),
		peers:         make(map[NoisePublicKey]*PeerInfo),
		packetPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 2048)
			},
		},
	}

	h.cookieChecker.Init(pubKey)
	h.cookieGenerator.Init(pubKey)

	return h, nil
}

// PublicKey returns the handler's public key.
func (h *Handler) PublicKey() NoisePublicKey {
	return h.publicKey
}

// AddPeer authorizes a peer by public key.
func (h *Handler) AddPeer(peerKey NoisePublicKey) {
	h.peersMutex.Lock()
	defer h.peersMutex.Unlock()

	if _, exists := h.peers[peerKey]; exists {
		return
	}

	peerInfo := &PeerInfo{
		PublicKey: peerKey,
		CreatedAt: now(),
	}
	peerInfo.cookieGen.Init(peerKey)
	h.peers[peerKey] = peerInfo
}

// AddPeerWithPSK authorizes a peer with a preshared key.
func (h *Handler) AddPeerWithPSK(peerKey NoisePublicKey, psk NoisePresharedKey) {
	h.peersMutex.Lock()
	defer h.peersMutex.Unlock()

	peerInfo := &PeerInfo{
		PublicKey:    peerKey,
		PresharedKey: psk,
		HasPSK:       true,
		CreatedAt:    now(),
	}
	peerInfo.cookieGen.Init(peerKey)
	h.peers[peerKey] = peerInfo
}

// RemovePeer removes a peer from the authorized list and tears down its session.
func (h *Handler) RemovePeer(peerKey NoisePublicKey) {
	h.peersMutex.Lock()
	delete(h.peers, peerKey)
	h.peersMutex.Unlock()

	// Also clean up session
	h.sessionsMutex.Lock()
	if session, exists := h.sessions[peerKey]; exists {
		session.mutex.Lock()
		if session.keypairCurrent != nil {
			h.keypairsMutex.Lock()
			delete(h.keypairs, session.keypairCurrent.localIndex)
			h.keypairsMutex.Unlock()
		}
		if session.keypairPrev != nil {
			h.keypairsMutex.Lock()
			delete(h.keypairs, session.keypairPrev.localIndex)
			h.keypairsMutex.Unlock()
		}
		if session.keypairNext != nil {
			h.keypairsMutex.Lock()
			delete(h.keypairs, session.keypairNext.localIndex)
			h.keypairsMutex.Unlock()
		}
		session.mutex.Unlock()
		delete(h.sessions, peerKey)
	}
	h.sessionsMutex.Unlock()
}

// IsAuthorizedPeer checks if a peer's public key is authorized.
// Returns false if the peer is unknown or has passed its ExpiresAt time.
func (h *Handler) IsAuthorizedPeer(peerKey NoisePublicKey) bool {
	h.peersMutex.RLock()
	info, exists := h.peers[peerKey]
	h.peersMutex.RUnlock()

	if !exists {
		return false
	}

	if !info.ExpiresAt.IsZero() && now().After(info.ExpiresAt) {
		return false
	}

	return true
}

// getPresharedKey returns the preshared key for a peer, or zero if none.
func (h *Handler) getPresharedKey(peerKey NoisePublicKey) NoisePresharedKey {
	h.peersMutex.RLock()
	info, exists := h.peers[peerKey]
	h.peersMutex.RUnlock()

	if exists && info.HasPSK {
		return info.PresharedKey
	}
	return NoisePresharedKey{}
}

// ProcessPacket processes an incoming WireGuard packet and returns the result.
// It dispatches by message type: initiation (1), response (2), cookie reply (3),
// and transport data (4). The caller is responsible for sending any Response
// bytes back to remoteAddr. Returns nil, nil for cookie replies (the cookie is
// stored internally for the next initiation attempt).
func (h *Handler) ProcessPacket(data []byte, remoteAddr *net.UDPAddr) (*PacketResult, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	msgType := binary_le_uint32(data[0:4])

	switch msgType {
	case MessageInitiationType:
		return h.processHandshakeInitiation(data, remoteAddr)
	case MessageResponseType:
		return h.processHandshakeResponse(data)
	case MessageCookieReplyType:
		return h.processCookieReply(data)
	case MessageTransportType:
		return h.processDataPacket(data)
	default:
		return nil, fmt.Errorf("unknown message type: %d", msgType)
	}
}

// Encrypt encrypts data for transmission to a peer.
func (h *Handler) Encrypt(data []byte, peerKey NoisePublicKey) ([]byte, error) {
	return h.encryptDataPacket(data, peerKey)
}

// GenerateKeepalive generates a keepalive packet for a peer.
func (h *Handler) GenerateKeepalive(peerKey NoisePublicKey) ([]byte, error) {
	return h.encryptDataPacket([]byte{}, peerKey)
}

// Maintenance performs periodic cleanup: rotates the cookie secret, removes
// stale pending handshakes, and expires inactive sessions. Call this
// periodically (e.g. every 10s). The Server calls it automatically.
func (h *Handler) Maintenance() {
	// Rotate cookie secret if needed
	h.cookieChecker.Lock()
	if time.Since(h.cookieChecker.mac2.secretSet) > CookieRefreshTime {
		if _, err := cryptoRandRead(h.cookieChecker.mac2.secret[:]); err != nil {
			slog.Error("wgnet: failed to rotate cookie secret", "error", err)
		} else {
			h.cookieChecker.mac2.secretSet = now()
		}
	}
	h.cookieChecker.Unlock()

	h.cleanupHandshakes()
	h.cleanupSessions()
}

// cleanupHandshakes removes pending handshakes older than RejectAfterTime.
func (h *Handler) cleanupHandshakes() {
	h.handshakesMutex.Lock()
	defer h.handshakesMutex.Unlock()

	if len(h.handshakes) == 0 {
		return
	}

	n := now()
	for idx, hs := range h.handshakes {
		if n.Sub(hs.created) > RejectAfterTime {
			delete(h.handshakes, idx)
		}
	}
}

// Close clears all pending handshakes, sessions, and keypairs. It does not
// affect peer authorization — peers remain in the authorized list.
func (h *Handler) Close() error {
	h.handshakesMutex.Lock()
	for key := range h.handshakes {
		delete(h.handshakes, key)
	}
	h.handshakesMutex.Unlock()

	h.sessionsMutex.Lock()
	for key := range h.sessions {
		delete(h.sessions, key)
	}
	h.sessionsMutex.Unlock()

	h.keypairsMutex.Lock()
	for key := range h.keypairs {
		delete(h.keypairs, key)
	}
	h.keypairsMutex.Unlock()

	return nil
}

// cleanupSessions removes sessions that have been inactive for longer than RejectAfterTime.
func (h *Handler) cleanupSessions() {
	h.sessionsMutex.Lock()
	defer h.sessionsMutex.Unlock()

	n := now()
	for key, session := range h.sessions {
		session.mutex.RLock()
		lastActive := session.lastReceived
		if session.lastSent.After(lastActive) {
			lastActive = session.lastSent
		}
		session.mutex.RUnlock()

		if n.Sub(lastActive) > RejectAfterTime {
			session.mutex.Lock()
			if session.keypairCurrent != nil {
				h.keypairsMutex.Lock()
				delete(h.keypairs, session.keypairCurrent.localIndex)
				h.keypairsMutex.Unlock()
			}
			if session.keypairPrev != nil {
				h.keypairsMutex.Lock()
				delete(h.keypairs, session.keypairPrev.localIndex)
				h.keypairsMutex.Unlock()
			}
			if session.keypairNext != nil {
				h.keypairsMutex.Lock()
				delete(h.keypairs, session.keypairNext.localIndex)
				h.keypairsMutex.Unlock()
			}
			session.mutex.Unlock()
			delete(h.sessions, key)
		}
	}
}

func (h *Handler) incrementActiveHandshakes() {
	h.handshakeMutex.Lock()
	defer h.handshakeMutex.Unlock()

	h.activeHandshakes++

	if h.activeHandshakes > DefaultLoadThreshold {
		h.loadMutex.Lock()
		h.underLoad = true
		h.loadMutex.Unlock()
	}
}

func (h *Handler) decrementActiveHandshakes() {
	h.handshakeMutex.Lock()
	defer h.handshakeMutex.Unlock()

	if h.activeHandshakes > 0 {
		h.activeHandshakes--
	}

	if h.activeHandshakes < DefaultLoadThreshold/2 {
		h.loadMutex.Lock()
		wasLoaded := h.underLoad
		h.underLoad = false
		h.loadMutex.Unlock()

		if wasLoaded {
			slog.Debug("wgnet: no longer under load", "active_handshakes", h.activeHandshakes)
		}
	}
}

func (h *Handler) isUnderLoad() bool {
	h.loadMutex.RLock()
	defer h.loadMutex.RUnlock()
	return h.underLoad
}

// hasHandshakeIndex reports whether this handler has a pending handshake with the given local index.
func (h *Handler) hasHandshakeIndex(idx uint32) bool {
	h.handshakesMutex.RLock()
	_, exists := h.handshakes[idx]
	h.handshakesMutex.RUnlock()
	return exists
}

// hasKeypairIndex reports whether this handler owns a keypair with the given local index.
func (h *Handler) hasKeypairIndex(idx uint32) bool {
	h.keypairsMutex.RLock()
	_, exists := h.keypairs[idx]
	h.keypairsMutex.RUnlock()
	return exists
}

// cryptoRandRead is a wrapper for testing.
var cryptoRandRead = func(b []byte) (int, error) {
	return rand.Read(b)
}
