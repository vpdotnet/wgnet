// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

// Package wgnet implements a WireGuard point-to-point endpoint library.
//
// Unlike the standard WireGuard implementation which is designed for multipoint
// networks, wgnet focuses on simple client/server endpoint connections.
package wgnet

import (
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// WireGuard protocol constants
const (
	// Protocol labels
	wgLabelMAC1   = "mac1----"
	wgLabelCookie = "cookie--"

	// Noise parameters
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"

	// TAI64N timestamp size (8 bytes seconds + 4 bytes nanoseconds)
	tai64nTimestampSize = 12

	// Message types
	messageInitiationType  = 1
	messageResponseType    = 2
	messageCookieReplyType = 3
	messageTransportType   = 4

	// Message sizes
	messageInitiationSize      = 148
	messageResponseSize        = 92
	messageCookieReplySize     = 64
	messageTransportHeaderSize = 16
	messageTransportSize       = messageTransportHeaderSize + chacha20poly1305.Overhead
	messageKeepaliveSize       = messageTransportSize

	// Transport message offsets
	messageTransportOffsetReceiver = 4
	messageTransportOffsetCounter  = 8
	messageTransportOffsetContent  = 16

	// Handshake timing
	handshakeInitiationRate = 20 * time.Millisecond
	rekeyAttemptTime        = 90 * time.Second
	rekeyTimeout            = 5 * time.Second
	keepaliveTimeout        = 10 * time.Second

	// CookieRefreshTime is the maximum lifetime of a cookie secret.
	CookieRefreshTime = 120 * time.Second

	// RejectAfterTime is how long sessions and pending handshakes are kept
	// before being cleaned up by Maintenance.
	RejectAfterTime = 180 * time.Second

	// DoS mitigation
	defaultLoadThreshold = 100

	// Key sizes
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32

	// WindowSize is the size of the replay protection sliding window.
	WindowSize = 8192
)

// NoisePublicKey is a Curve25519 public key.
type NoisePublicKey [32]byte

// String returns the base64-encoded public key (WireGuard standard encoding).
func (pk NoisePublicKey) String() string {
	return base64.StdEncoding.EncodeToString(pk[:])
}

// MarshalText implements encoding.TextMarshaler.
func (pk NoisePublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(pk[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (pk *NoisePublicKey) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(b) != NoisePublicKeySize {
		return fmt.Errorf("invalid key length: got %d, want %d", len(b), NoisePublicKeySize)
	}
	copy(pk[:], b)
	return nil
}

// NoisePrivateKey is a Curve25519 private key.
type NoisePrivateKey [32]byte

// String returns the base64-encoded private key.
func (sk NoisePrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(sk[:])
}

// MarshalText implements encoding.TextMarshaler.
func (sk NoisePrivateKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(sk[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (sk *NoisePrivateKey) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(b) != NoisePrivateKeySize {
		return fmt.Errorf("invalid key length: got %d, want %d", len(b), NoisePrivateKeySize)
	}
	copy(sk[:], b)
	return nil
}

// NoisePresharedKey is a WireGuard preshared key.
type NoisePresharedKey [32]byte

// MarshalText implements encoding.TextMarshaler.
func (psk NoisePresharedKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(psk[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (psk *NoisePresharedKey) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(b) != NoisePresharedKeySize {
		return fmt.Errorf("invalid key length: got %d, want %d", len(b), NoisePresharedKeySize)
	}
	copy(psk[:], b)
	return nil
}

// Wire protocol message structs (internal)

type messageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral [NoisePublicKeySize]byte
	Static    [NoisePublicKeySize + chacha20poly1305.Overhead]byte
	Timestamp [tai64nTimestampSize + chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type messageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral [NoisePublicKeySize]byte
	Empty     [chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type messageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type messageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + chacha20poly1305.Overhead]byte
}

// Handshake state enumeration
type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)
