// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the BSD 3-Clause License.
// See LICENSE file in the project root for full license information.

// Package wgnet implements a WireGuard point-to-point endpoint library.
//
// Unlike the standard WireGuard implementation which is designed for multipoint
// networks, wgnet focuses on simple client/server endpoint connections.
package wgnet

import (
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
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4

	// Message sizes
	MessageInitiationSize      = 148
	MessageResponseSize        = 92
	MessageCookieReplySize     = 64
	MessageTransportHeaderSize = 16
	MessageTransportSize       = MessageTransportHeaderSize + chacha20poly1305.Overhead
	MessageKeepaliveSize       = MessageTransportSize

	// Transport message offsets
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16

	// Handshake timing
	HandshakeInitiationRate = 20 * time.Millisecond
	RekeyAttemptTime        = 90 * time.Second
	RekeyTimeout            = 5 * time.Second
	KeepaliveTimeout        = 10 * time.Second
	CookieRefreshTime       = 120 * time.Second
	RejectAfterTime         = 180 * time.Second

	// DoS mitigation
	DefaultLoadThreshold = 100

	// Key sizes
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32

	// Replay protection window
	WindowSize = 8192
)

// NoisePublicKey is a Curve25519 public key.
type NoisePublicKey [32]byte

// NoisePrivateKey is a Curve25519 private key.
type NoisePrivateKey [32]byte

// NoisePresharedKey is a WireGuard preshared key.
type NoisePresharedKey [32]byte

// Message structs for WireGuard protocol

// MessageInitiation represents a handshake initiation message.
type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral [NoisePublicKeySize]byte
	Static    [NoisePublicKeySize + chacha20poly1305.Overhead]byte
	Timestamp [tai64nTimestampSize + chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

// MessageResponse represents a handshake response message.
type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral [NoisePublicKeySize]byte
	Empty     [chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

// MessageTransport represents a data transport message.
type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

// MessageCookieReply represents a cookie reply message.
type MessageCookieReply struct {
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
