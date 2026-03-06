// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// processDataPacket decrypts an incoming type-4 transport data packet. It looks
// up the keypair by receiver index, checks for replay, and decrypts the payload.
// Empty payloads are returned as PacketKeepalive.
func (h *Handler) processDataPacket(data []byte) (*PacketResult, error) {
	if len(data) < messageTransportHeaderSize {
		return nil, fmt.Errorf("data packet too short: %d", len(data))
	}

	msgType := binary_le_uint32(data[0:4])
	if msgType != messageTransportType {
		return nil, fmt.Errorf("invalid message type: %d (expected %d)", msgType, messageTransportType)
	}

	receiverIdx := binary_le_uint32(data[4:8])
	counter := binary_le_uint64(data[8:16])

	// Find keypair
	h.keypairsMutex.RLock()
	kp, exists := h.keypairs[receiverIdx]
	h.keypairsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no keypair for receiver index: %d", receiverIdx)
	}

	// Create nonce from counter
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Check for replay
	if kp.replayFilter.CheckReplay(counter) {
		return nil, fmt.Errorf("replay detected for counter: %d", counter)
	}

	// Decrypt in-place
	ciphertext := data[16:]
	plaintext, err := kp.receive.Open(ciphertext[:0], nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	// Find peer key for this keypair by looking up sessions
	var peerKey NoisePublicKey
	h.sessionsMutex.RLock()
	for pk, sess := range h.sessions {
		sess.mutex.RLock()
		match := (sess.keypairCurrent != nil && sess.keypairCurrent.localIndex == receiverIdx) ||
			(sess.keypairPrev != nil && sess.keypairPrev.localIndex == receiverIdx)
		sess.mutex.RUnlock()
		if match {
			peerKey = pk
			break
		}
	}
	h.sessionsMutex.RUnlock()

	// Update session last received time
	h.sessionsMutex.RLock()
	if sess, exists := h.sessions[peerKey]; exists {
		sess.mutex.Lock()
		sess.lastReceived = now()
		sess.mutex.Unlock()
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

// encryptDataPacket encrypts data for transmission to a peer and returns a
// complete type-4 transport packet. Pass empty data to generate a keepalive.
func (h *Handler) encryptDataPacket(data []byte, peerKey NoisePublicKey) ([]byte, error) {
	// Find session
	h.sessionsMutex.RLock()
	sess, exists := h.sessions[peerKey]
	if !exists {
		h.sessionsMutex.RUnlock()
		return nil, fmt.Errorf("no session for peer")
	}
	h.sessionsMutex.RUnlock()

	// Get current keypair
	sess.mutex.Lock()
	kp := sess.keypairCurrent
	if kp == nil {
		sess.mutex.Unlock()
		return nil, fmt.Errorf("no current keypair for peer")
	}
	remoteIndex := kp.remoteIndex
	sess.lastSent = now()
	sess.mutex.Unlock()

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
	ciphertext := kp.send.Seal(nil, nonce[:], data, nil)

	// Build packet
	result := make([]byte, messageTransportHeaderSize+len(ciphertext))
	binary_le_put_uint32(result[0:4], messageTransportType)
	binary_le_put_uint32(result[4:8], remoteIndex)
	binary_le_put_uint64(result[8:16], counter)
	copy(result[messageTransportHeaderSize:], ciphertext)

	return result, nil
}
