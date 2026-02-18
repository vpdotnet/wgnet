// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// processHandshakeInitiation processes a handshake initiation from a peer.
func (h *Handler) processHandshakeInitiation(data []byte, remoteAddr *net.UDPAddr) (*PacketResult, error) {
	h.incrementActiveHandshakes()
	defer h.decrementActiveHandshakes()

	// Decode the initiation message
	msg, err := decodeMessageInitiation(data)
	if err != nil {
		return nil, fmt.Errorf("decode handshake: %w", err)
	}

	// Validate MAC1
	if !h.cookieChecker.CheckMAC1(data) {
		if h.isUnderLoad() {
			cookieReply, err := h.GenerateCookieReply(remoteAddr.IP, data[116:132])
			if err != nil {
				return nil, fmt.Errorf("generate cookie reply: %w", err)
			}
			return &PacketResult{Type: PacketCookieReply, Response: cookieReply}, nil
		}
		return nil, fmt.Errorf("invalid MAC1")
	}

	// Validate MAC2 if under load
	if h.isUnderLoad() {
		if !isZero(data[132:148]) {
			ipBytes := remoteAddr.IP.To4()
			if ipBytes == nil {
				ipBytes = remoteAddr.IP.To16()
			}

			if !h.cookieChecker.CheckMAC2(data, ipBytes) {
				cookieReply, err := h.GenerateCookieReply(remoteAddr.IP, data[116:132])
				if err != nil {
					return nil, fmt.Errorf("generate cookie reply: %w", err)
				}
				return &PacketResult{Type: PacketCookieReply, Response: cookieReply}, nil
			}
		} else {
			cookieReply, err := h.GenerateCookieReply(remoteAddr.IP, data[116:132])
			if err != nil {
				return nil, fmt.Errorf("generate cookie reply: %w", err)
			}
			return &PacketResult{Type: PacketCookieReply, Response: cookieReply}, nil
		}
	}

	serverPrivateKey := h.privateKey
	serverPublicKey := h.publicKey

	// === Handshake state ===
	var hs Handshake
	hs.chainKey = initialChainKey
	hs.hash = initialHash
	hs.remoteIndex = msg.Sender

	// Mix server public key into hash
	mixHash(&hs.hash, &hs.hash, serverPublicKey[:])

	// Extract client's ephemeral key
	copy(hs.remoteEphemeral[:], msg.Ephemeral[:])
	mixHash(&hs.hash, &hs.hash, hs.remoteEphemeral[:])
	mixKey(&hs.chainKey, &hs.chainKey, hs.remoteEphemeral[:])

	// === Decrypt static key ===
	var key [chacha20poly1305.KeySize]byte
	tempSS, err := curve25519.X25519(serverPrivateKey[:], hs.remoteEphemeral[:])
	if err != nil {
		return nil, fmt.Errorf("DH failed: %w", err)
	}

	kdf2(&hs.chainKey, &key, hs.chainKey[:], tempSS)

	aeadCipher, _ := chacha20poly1305.New(key[:])
	clientStaticKey, err := aeadCipher.Open(nil, zeroNonce[:], msg.Static[:], hs.hash[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt static key: %w", err)
	}

	if len(clientStaticKey) != 32 {
		return nil, fmt.Errorf("invalid client static key length: %d", len(clientStaticKey))
	}

	copy(hs.remoteStatic[:], clientStaticKey)
	mixHash(&hs.hash, &hs.hash, msg.Static[:])

	// === Static-static DH ===
	tempSS, err = curve25519.X25519(serverPrivateKey[:], hs.remoteStatic[:])
	if err != nil {
		return nil, fmt.Errorf("static DH failed: %w", err)
	}

	copy(hs.precomputedStaticStatic[:], tempSS)
	kdf2(&hs.chainKey, &key, hs.chainKey[:], tempSS)

	// === Decrypt timestamp ===
	aeadCipher, _ = chacha20poly1305.New(key[:])
	_, err = aeadCipher.Open(nil, zeroNonce[:], msg.Timestamp[:], hs.hash[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt timestamp: %w", err)
	}

	mixHash(&hs.hash, &hs.hash, msg.Timestamp[:])

	// === Peer authorization ===
	if !h.IsAuthorizedPeer(hs.remoteStatic) {
		if h.onUnknownPeer != nil && h.onUnknownPeer(hs.remoteStatic, remoteAddr) {
			// Callback authorized the peer, add it
			h.AddPeer(hs.remoteStatic)
		} else {
			return nil, fmt.Errorf("unauthorized peer")
		}
	}

	// Update last handshake time
	h.peersMutex.RLock()
	if info, exists := h.peers[hs.remoteStatic]; exists {
		info.LastHandshake = now()
	}
	h.peersMutex.RUnlock()

	// === Prepare response ===
	var respMsg MessageResponse
	respMsg.Type = MessageResponseType

	var senderIdx uint32
	for senderIdx == 0 {
		if err := binary.Read(rand.Reader, binary.LittleEndian, &senderIdx); err != nil {
			senderIdx = uint32(now().UnixNano())
		}
	}

	respMsg.Sender = senderIdx
	respMsg.Receiver = msg.Sender

	// === Generate ephemeral key ===
	hs.localEphemeral, err = GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	ephemeralPub := hs.localEphemeral.PublicKey()
	copy(respMsg.Ephemeral[:], ephemeralPub[:])

	mixHash(&hs.hash, &hs.hash, ephemeralPub[:])
	mixKey(&hs.chainKey, &hs.chainKey, ephemeralPub[:])

	// === DH operations ===
	// ee: ephemeral-ephemeral
	tempSS, err = curve25519.X25519(hs.localEphemeral[:], hs.remoteEphemeral[:])
	if err != nil {
		return nil, fmt.Errorf("ee DH failed: %w", err)
	}
	mixKey(&hs.chainKey, &hs.chainKey, tempSS)

	// se: ephemeral-static
	tempSS, err = curve25519.X25519(hs.localEphemeral[:], hs.remoteStatic[:])
	if err != nil {
		return nil, fmt.Errorf("es DH failed: %w", err)
	}
	mixKey(&hs.chainKey, &hs.chainKey, tempSS)

	// === Preshared key ===
	psk := h.getPresharedKey(hs.remoteStatic)
	mixPSK(&hs.chainKey, &hs.hash, &key, psk)

	// === Encrypt empty message ===
	aeadCipher, _ = chacha20poly1305.New(key[:])
	emptyData := aeadCipher.Seal(nil, zeroNonce[:], []byte{}, hs.hash[:])

	if len(emptyData) != chacha20poly1305.Overhead {
		return nil, fmt.Errorf("invalid empty data size: %d", len(emptyData))
	}

	copy(respMsg.Empty[:], emptyData)
	mixHash(&hs.hash, &hs.hash, emptyData)

	// === MAC calculation ===
	for i := range respMsg.MAC1 {
		respMsg.MAC1[i] = 0
	}
	for i := range respMsg.MAC2 {
		respMsg.MAC2[i] = 0
	}

	macInput := make([]byte, 60)
	binary.LittleEndian.PutUint32(macInput[0:4], respMsg.Type)
	binary.LittleEndian.PutUint32(macInput[4:8], respMsg.Sender)
	binary.LittleEndian.PutUint32(macInput[8:12], respMsg.Receiver)
	copy(macInput[12:44], respMsg.Ephemeral[:])
	copy(macInput[44:60], respMsg.Empty[:])

	mac1Key := calculateMAC1Key(hs.remoteStatic)
	mac1Hasher, err := blake2s.New128(mac1Key[:])
	if err != nil {
		return nil, fmt.Errorf("create MAC1 hash: %w", err)
	}
	mac1Hasher.Write(macInput)
	mac1Hasher.Sum(respMsg.MAC1[:0])

	if !h.isUnderLoad() {
		for i := range respMsg.MAC2 {
			respMsg.MAC2[i] = 0
		}
	}

	// === Store handshake ===
	hs.localIndex = senderIdx
	hs.state = handshakeResponseCreated

	h.handshakesMutex.Lock()
	h.handshakes[senderIdx] = &hs
	h.handshakesMutex.Unlock()

	// === Derive transport keys ===
	// As responder: receive with first key, send with second
	var recvKey, sendKey [chacha20poly1305.KeySize]byte
	kdf2(&recvKey, &sendKey, hs.chainKey[:], nil)

	keypair := &Keypair{
		send:        createAEAD(sendKey),
		receive:     createAEAD(recvKey),
		created:     now(),
		localIndex:  hs.localIndex,
		remoteIndex: hs.remoteIndex,
		isInitiator: false,
	}
	keypair.replayFilter.Reset()

	h.keypairsMutex.Lock()
	h.keypairs[hs.localIndex] = keypair
	h.keypairsMutex.Unlock()

	// === Update session ===
	h.sessionsMutex.Lock()
	if session, exists := h.sessions[hs.remoteStatic]; exists {
		session.mutex.Lock()
		if session.keypairCurrent != nil {
			session.keypairPrev = session.keypairCurrent
		}
		session.keypairCurrent = keypair
		session.mutex.Unlock()
	} else {
		h.sessions[hs.remoteStatic] = &Session{
			peerKey:        hs.remoteStatic,
			keypairCurrent: keypair,
			lastReceived:   now(),
			lastSent:       now(),
		}
	}
	h.sessionsMutex.Unlock()

	// === Encode response ===
	respBytes, err := encodeMessageResponse(&respMsg)
	if err != nil {
		return nil, fmt.Errorf("encode response: %w", err)
	}

	if len(respBytes) != MessageResponseSize {
		return nil, fmt.Errorf("invalid response size: %d (expected %d)", len(respBytes), MessageResponseSize)
	}

	return &PacketResult{
		Type:     PacketHandshakeResponse,
		Response: respBytes,
		PeerKey:  hs.remoteStatic,
	}, nil
}

// decodeMessageInitiation deserializes a handshake initiation message.
func decodeMessageInitiation(data []byte) (*MessageInitiation, error) {
	if len(data) < MessageInitiationSize {
		return nil, fmt.Errorf("message too short: %d (expected %d)", len(data), MessageInitiationSize)
	}

	var msg MessageInitiation
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &msg); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return &msg, nil
}

// encodeMessageResponse serializes a handshake response message.
func encodeMessageResponse(msg *MessageResponse) ([]byte, error) {
	buf := bytes.Buffer{}
	if err := binary.Write(&buf, binary.LittleEndian, msg); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	return buf.Bytes(), nil
}

// HasSession returns true if there is an active session with the given peer.
func (h *Handler) HasSession(peerKey NoisePublicKey) bool {
	h.sessionsMutex.RLock()
	defer h.sessionsMutex.RUnlock()

	session, exists := h.sessions[peerKey]
	if !exists {
		return false
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()
	return session.keypairCurrent != nil
}

// SessionInfo returns timing information about a peer's session.
// Returns zero times if no session exists.
func (h *Handler) SessionInfo(peerKey NoisePublicKey) (lastReceived, lastSent time.Time, ok bool) {
	h.sessionsMutex.RLock()
	defer h.sessionsMutex.RUnlock()

	session, exists := h.sessions[peerKey]
	if !exists {
		return
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()

	return session.lastReceived, session.lastSent, true
}

// Peers returns the list of authorized peer public keys.
func (h *Handler) Peers() []NoisePublicKey {
	h.peersMutex.RLock()
	defer h.peersMutex.RUnlock()

	keys := make([]NoisePublicKey, 0, len(h.peers))
	for k := range h.peers {
		keys = append(keys, k)
	}
	return keys
}

// SetPeerExpiry sets an expiration time for a peer. After this time, the peer
// will no longer be authorized for new handshakes.
func (h *Handler) SetPeerExpiry(peerKey NoisePublicKey, expiresAt time.Time) {
	h.peersMutex.RLock()
	defer h.peersMutex.RUnlock()

	if info, exists := h.peers[peerKey]; exists {
		info.ExpiresAt = expiresAt
	}
}

func init() {
	// Verify protocol constant sizes at startup
	_ = [MessageInitiationSize]byte{}
	_ = [MessageResponseSize]byte{}
	_ = [MessageCookieReplySize]byte{}

	slog.Debug("wgnet: protocol constants initialized")
}
