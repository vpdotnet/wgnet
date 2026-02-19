// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"hash"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Global protocol constants computed at init time.
var (
	initialChainKey [blake2s.Size]byte
	initialHash     [blake2s.Size]byte
	zeroNonce       [chacha20poly1305.NonceSize]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
}

// Handshake represents the state of a WireGuard handshake.
type Handshake struct {
	state                   handshakeState
	hash                    [blake2s.Size]byte
	chainKey                [blake2s.Size]byte
	localEphemeral          NoisePrivateKey
	localIndex              uint32
	remoteIndex             uint32
	remoteStatic            NoisePublicKey
	remoteEphemeral         NoisePublicKey
	precomputedStaticStatic [NoisePublicKeySize]byte
	created                 time.Time
}

// Session represents a peer session with rotating keypairs.
type Session struct {
	keypairCurrent *Keypair
	keypairPrev    *Keypair
	keypairNext    *Keypair
	lastReceived   time.Time
	lastSent       time.Time
	peerKey        NoisePublicKey
	mutex          sync.RWMutex
}

// Keypair represents a derived keypair for transport data.
type Keypair struct {
	send         aead
	receive      aead
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
	replayFilter SlidingWindow
}

// aead is an interface for AEAD ciphers.
type aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// CookieChecker verifies MAC1/MAC2 on incoming messages.
type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		secret        [blake2s.Size]byte
		secretSet     time.Time
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

// CookieGenerator creates MAC1/MAC2 for outgoing messages.
type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		cookie        [blake2s.Size128]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [blake2s.Size128]byte
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

// Init initializes the CookieChecker with the local public key.
func (cc *CookieChecker) Init(pk NoisePublicKey) {
	cc.Lock()
	defer cc.Unlock()

	cc.mac1.key = calculateMAC1Key(pk)

	rand.Read(cc.mac2.secret[:])
	cc.mac2.secretSet = now()

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(wgLabelCookie))
		hash.Write(pk[:])
		hash.Sum(cc.mac2.encryptionKey[:0])
	}()
}

// CheckMAC1 verifies the MAC1 field of a message.
func (cc *CookieChecker) CheckMAC1(msg []byte) bool {
	cc.RLock()
	defer cc.RUnlock()

	size := len(msg)
	if size < blake2s.Size128*2 {
		return false
	}

	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	mac, err := blake2s.New128(cc.mac1.key[:])
	if err != nil {
		return false
	}

	mac.Write(msg[:smac1])

	var computed [blake2s.Size128]byte
	mac.Sum(computed[:0])

	return hmac.Equal(computed[:], msg[smac1:smac2])
}

// CheckMAC2 verifies the MAC2 field of a message.
func (cc *CookieChecker) CheckMAC2(msg []byte, src []byte) bool {
	cc.RLock()
	defer cc.RUnlock()

	if time.Since(cc.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	var cookie [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(cc.mac2.secret[:])
		mac.Write(src)
		mac.Sum(cookie[:0])
	}()

	smac2 := len(msg) - blake2s.Size128

	var mac2 [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(cookie[:])
		mac.Write(msg[:smac2])
		mac.Sum(mac2[:0])
	}()

	return hmac.Equal(mac2[:], msg[smac2:])
}

// Init initializes the CookieGenerator with the remote public key.
func (cg *CookieGenerator) Init(pk NoisePublicKey) {
	cg.Lock()
	defer cg.Unlock()

	cg.mac1.key = calculateMAC1Key(pk)

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(wgLabelCookie))
		hash.Write(pk[:])
		hash.Sum(cg.mac2.encryptionKey[:0])
	}()

	cg.mac2.cookieSet = time.Time{}
}

// AddMacs adds MAC1 and MAC2 to a message.
func (cg *CookieGenerator) AddMacs(msg []byte) {
	size := len(msg)

	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	cg.Lock()
	defer cg.Unlock()

	func() {
		mac, _ := blake2s.New128(cg.mac1.key[:])
		mac.Write(msg[:smac1])
		mac.Sum(mac1[:0])
	}()
	copy(cg.mac2.lastMAC1[:], mac1)
	cg.mac2.hasLastMAC1 = true

	if time.Since(cg.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	func() {
		mac, _ := blake2s.New128(cg.mac2.cookie[:])
		mac.Write(msg[:smac2])
		mac.Sum(mac2[:0])
	}()
}

// GenerateCookieReply generates a cookie reply message for DoS mitigation.
// receiverIdx is the sender index from the incoming initiation message,
// used to populate the Receiver field so the initiator can match the reply.
func (h *Handler) GenerateCookieReply(clientIP net.IP, receiverIdx uint32, initMAC1 []byte) ([]byte, error) {
	msg := make([]byte, MessageCookieReplySize)

	binary_le_put_uint32(msg[0:4], MessageCookieReplyType)
	binary_le_put_uint32(msg[4:8], receiverIdx)

	if _, err := rand.Read(msg[8:32]); err != nil {
		return nil, err
	}

	serverPublicKey := h.publicKey

	ipBytes := clientIP.To4()
	if ipBytes == nil {
		ipBytes = clientIP.To16()
	}

	h.cookieChecker.RLock()

	mac, err := blake2s.New128(h.cookieChecker.mac2.secret[:])
	if err != nil {
		h.cookieChecker.RUnlock()
		return nil, err
	}

	mac.Write(ipBytes)
	var cookie [blake2s.Size128]byte
	mac.Sum(cookie[:0])

	h.cookieChecker.RUnlock()

	cookieKey := blake2s.Sum256(append([]byte(wgLabelCookie), serverPublicKey[:]...))

	xaead, err := chacha20poly1305.NewX(cookieKey[:])
	if err != nil {
		return nil, err
	}

	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[:], msg[8:32])

	encryptedCookie := xaead.Seal(nil, nonce[:], cookie[:], initMAC1)

	copy(msg[32:], encryptedCookie)

	return msg, nil
}

// calculateMAC1Key computes the MAC1 key from a public key.
func calculateMAC1Key(publicKey NoisePublicKey) [32]byte {
	var key [32]byte
	hash, _ := blake2s.New256(nil)
	hash.Write([]byte(wgLabelMAC1))
	hash.Write(publicKey[:])
	hash.Sum(key[:0])
	return key
}

// mixHash mixes data into the hash.
func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
}

// mixKey mixes a key with input.
func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	kdf1(dst, c[:], data)
}

// kdf1 derives a single key from input.
func kdf1(t0 *[blake2s.Size]byte, key, input []byte) {
	hmac1(t0, key, input)
	hmac1(t0, t0[:], []byte{0x1})
}

// kdf2 derives two keys from input.
func kdf2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, input)
	hmac1(t0, prk[:], []byte{0x1})
	hmac2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

// kdf3 derives three keys from input.
func kdf3(t0, t1, t2 *[blake2s.Size]byte, data []byte, key []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, data)

	hmac1(t0, prk[:], []byte{1})

	var data2 [blake2s.Size + 1]byte
	copy(data2[:], t0[:])
	data2[blake2s.Size] = 2
	hmac1(t1, prk[:], data2[:])

	if t2 != nil {
		var data3 [blake2s.Size + 1]byte
		copy(data3[:], t1[:])
		data3[blake2s.Size] = 3
		hmac1(t2, prk[:], data3[:])
	}

	setZero(prk[:])
}

// mixPSK mixes a pre-shared key into the handshake.
func mixPSK(chainingKey, hash *[blake2s.Size]byte, key *[chacha20poly1305.KeySize]byte, psk NoisePresharedKey) {
	var tau [blake2s.Size]byte
	kdf3(chainingKey, &tau, key, psk[:], chainingKey[:])
	mixHash(hash, hash, tau[:])
}

func hmac1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func hmac2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

// clamp applies the Curve25519 clamping operation to a private key.
func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

// PublicKey derives the public key from this private key.
func (sk NoisePrivateKey) PublicKey() NoisePublicKey {
	var pk NoisePublicKey
	result, _ := curve25519.X25519(sk[:], curve25519.Basepoint)
	copy(pk[:], result)
	return pk
}

// GeneratePrivateKey generates a new random Curve25519 private key.
func GeneratePrivateKey() (NoisePrivateKey, error) {
	var key NoisePrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	key.clamp()
	return key, nil
}

// createAEAD creates an AEAD cipher from a key.
func createAEAD(key [chacha20poly1305.KeySize]byte) aead {
	a, _ := chacha20poly1305.New(key[:])
	return a
}

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func isZero(arr []byte) bool {
	acc := 1
	for _, v := range arr {
		acc &= subtle.ConstantTimeByteEq(v, 0)
	}
	return acc == 1
}

// binary helpers to avoid importing encoding/binary in every file
func binary_le_put_uint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func binary_le_uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func binary_le_uint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func binary_le_put_uint64(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}
