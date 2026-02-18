// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the BSD 3-Clause License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// processDataPacket decrypts an incoming transport data packet.
func (h *Handler) processDataPacket(data []byte) (*PacketResult, error) {
	if len(data) < MessageTransportHeaderSize {
		return nil, fmt.Errorf("data packet too short: %d", len(data))
	}

	msgType := binary_le_uint32(data[0:4])
	if msgType != MessageTransportType {
		return nil, fmt.Errorf("invalid message type: %d (expected %d)", msgType, MessageTransportType)
	}

	receiverIdx := binary_le_uint32(data[4:8])
	counter := binary_le_uint64(data[8:16])

	// Find keypair
	h.keypairsMutex.RLock()
	keypair, exists := h.keypairs[receiverIdx]
	h.keypairsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no keypair for receiver index: %d", receiverIdx)
	}

	// Create nonce from counter
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Check for replay
	if keypair.replayFilter.CheckReplay(counter) {
		return nil, fmt.Errorf("replay detected for counter: %d", counter)
	}

	// Decrypt in-place
	ciphertext := data[16:]
	plaintext, err := keypair.receive.Open(ciphertext[:0], nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	// Find peer key for this keypair by looking up sessions
	var peerKey NoisePublicKey
	h.sessionsMutex.RLock()
	for pk, session := range h.sessions {
		session.mutex.RLock()
		match := (session.keypairCurrent != nil && session.keypairCurrent.localIndex == receiverIdx) ||
			(session.keypairPrev != nil && session.keypairPrev.localIndex == receiverIdx)
		session.mutex.RUnlock()
		if match {
			peerKey = pk
			break
		}
	}
	h.sessionsMutex.RUnlock()

	// Update session last received time
	h.sessionsMutex.RLock()
	if session, exists := h.sessions[peerKey]; exists {
		session.mutex.Lock()
		session.lastReceived = now()
		session.mutex.Unlock()
	}
	h.sessionsMutex.RUnlock()

	resultType := PacketTransportData
	if len(plaintext) == 0 {
		resultType = PacketKeepalive
	}

	return &PacketResult{
		Type:    resultType,
		Data:    plaintext,
		PeerKey: peerKey,
	}, nil
}

// encryptDataPacket encrypts data for transmission to a peer.
func (h *Handler) encryptDataPacket(data []byte, peerKey NoisePublicKey) ([]byte, error) {
	// Find session
	h.sessionsMutex.RLock()
	session, exists := h.sessions[peerKey]
	if !exists {
		h.sessionsMutex.RUnlock()
		return nil, fmt.Errorf("no session for peer")
	}
	h.sessionsMutex.RUnlock()

	// Get current keypair
	session.mutex.Lock()
	keypair := session.keypairCurrent
	if keypair == nil {
		session.mutex.Unlock()
		return nil, fmt.Errorf("no current keypair for peer")
	}
	remoteIndex := keypair.remoteIndex
	session.lastSent = now()
	session.mutex.Unlock()

	// Increment counter
	h.countersMutex.Lock()
	counter := h.peerCounters[peerKey]
	counter++
	h.peerCounters[peerKey] = counter
	h.countersMutex.Unlock()

	// Create nonce from counter
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Encrypt
	ciphertext := keypair.send.Seal(nil, nonce[:], data, nil)

	// Build packet
	result := make([]byte, MessageTransportHeaderSize+len(ciphertext))
	binary_le_put_uint32(result[0:4], MessageTransportType)
	binary_le_put_uint32(result[4:8], remoteIndex)
	binary_le_put_uint64(result[8:16], counter)
	copy(result[MessageTransportHeaderSize:], ciphertext)

	return result, nil
}
