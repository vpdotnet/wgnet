package wgnet

import (
	"net"
	"testing"
	"time"
)

func TestAddPeerWithPSK(t *testing.T) {
	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	peer, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler peer: %v", err)
	}
	defer peer.Close()

	var psk NoisePresharedKey
	copy(psk[:], []byte("01234567890123456789012345678901"))

	h.AddPeerWithPSK(peer.PublicKey(), psk)

	// Verify peer is authorized.
	if !h.IsAuthorizedPeer(peer.PublicKey()) {
		t.Fatal("peer should be authorized")
	}

	// Verify getPresharedKey returns the PSK.
	got := h.getPresharedKey(peer.PublicKey())
	if got != psk {
		t.Fatalf("PSK mismatch: got %x, want %x", got, psk)
	}

	// Verify getPresharedKey returns zero for unknown peer.
	unknown, _ := NewHandler(Config{})
	defer unknown.Close()
	if got := h.getPresharedKey(unknown.PublicKey()); got != (NoisePresharedKey{}) {
		t.Fatalf("expected zero PSK for unknown peer, got %x", got)
	}
}

func TestRemovePeer(t *testing.T) {
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	server, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler server: %v", err)
	}
	defer server.Close()

	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// Perform full handshake.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	serverResult, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server ProcessPacket: %v", err)
	}

	_, err = client.ProcessPacket(serverResult.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client ProcessPacket: %v", err)
	}

	// Verify session exists.
	if !server.HasSession(client.PublicKey()) {
		t.Fatal("server should have session with client")
	}

	// Count keypairs before removal.
	server.keypairsMutex.RLock()
	kpCountBefore := len(server.keypairs)
	server.keypairsMutex.RUnlock()
	if kpCountBefore == 0 {
		t.Fatal("server should have keypairs before removal")
	}

	// Remove the peer.
	server.RemovePeer(client.PublicKey())

	// Verify peer is no longer authorized.
	if server.IsAuthorizedPeer(client.PublicKey()) {
		t.Fatal("peer should no longer be authorized")
	}

	// Verify session is gone.
	if server.HasSession(client.PublicKey()) {
		t.Fatal("session should be removed")
	}

	// Verify keypairs are cleaned up.
	server.keypairsMutex.RLock()
	kpCountAfter := len(server.keypairs)
	server.keypairsMutex.RUnlock()
	if kpCountAfter != 0 {
		t.Fatalf("expected 0 keypairs after removal, got %d", kpCountAfter)
	}
}

func TestPeers(t *testing.T) {
	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	// No peers initially.
	if len(h.Peers()) != 0 {
		t.Fatal("expected no peers initially")
	}

	// Add peers.
	var peers [3]*Handler
	for i := range peers {
		p, err := NewHandler(Config{})
		if err != nil {
			t.Fatalf("NewHandler peer %d: %v", i, err)
		}
		defer p.Close()
		peers[i] = p
		h.AddPeer(p.PublicKey())
	}

	got := h.Peers()
	if len(got) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(got))
	}

	// Verify all peer keys are present.
	peerSet := make(map[NoisePublicKey]bool)
	for _, k := range got {
		peerSet[k] = true
	}
	for i, p := range peers {
		if !peerSet[p.PublicKey()] {
			t.Fatalf("peer %d not found in Peers()", i)
		}
	}
}

func TestSessionInfo(t *testing.T) {
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	server, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler server: %v", err)
	}
	defer server.Close()

	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// No session yet.
	_, _, ok := server.SessionInfo(client.PublicKey())
	if ok {
		t.Fatal("should not have session info before handshake")
	}

	// Perform handshake.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	serverResult, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server ProcessPacket: %v", err)
	}

	_, err = client.ProcessPacket(serverResult.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client ProcessPacket: %v", err)
	}

	// Session info should now be available.
	lastRecv, lastSent, ok := server.SessionInfo(client.PublicKey())
	if !ok {
		t.Fatal("expected session info after handshake")
	}
	if lastRecv.IsZero() {
		t.Fatal("lastReceived should not be zero")
	}
	if lastSent.IsZero() {
		t.Fatal("lastSent should not be zero")
	}
}

func TestSetPeerExpiry(t *testing.T) {
	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	peer, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler peer: %v", err)
	}
	defer peer.Close()

	h.AddPeer(peer.PublicKey())

	// Peer should be authorized.
	if !h.IsAuthorizedPeer(peer.PublicKey()) {
		t.Fatal("peer should be authorized")
	}

	// Set expiry in the past.
	h.SetPeerExpiry(peer.PublicKey(), time.Now().Add(-time.Hour))

	if h.IsAuthorizedPeer(peer.PublicKey()) {
		t.Fatal("peer should not be authorized after expiry in the past")
	}

	// Set expiry in the future.
	h.SetPeerExpiry(peer.PublicKey(), time.Now().Add(time.Hour))

	if !h.IsAuthorizedPeer(peer.PublicKey()) {
		t.Fatal("peer should be authorized with future expiry")
	}
}

func TestGenerateKeepalive(t *testing.T) {
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	server, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler server: %v", err)
	}
	defer server.Close()

	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// Perform handshake.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	serverResult, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server ProcessPacket: %v", err)
	}

	_, err = client.ProcessPacket(serverResult.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client ProcessPacket: %v", err)
	}

	// Generate keepalive from client.
	keepalivePkt, err := client.GenerateKeepalive(server.PublicKey())
	if err != nil {
		t.Fatalf("GenerateKeepalive: %v", err)
	}

	// Verify it's a valid transport packet.
	if len(keepalivePkt) < messageTransportHeaderSize {
		t.Fatalf("keepalive too short: %d", len(keepalivePkt))
	}
	msgType := binary_le_uint32(keepalivePkt[0:4])
	if msgType != messageTransportType {
		t.Fatalf("expected transport type %d, got %d", messageTransportType, msgType)
	}

	// Server should be able to process it as a keepalive.
	result, err := server.ProcessPacket(keepalivePkt, remoteAddr)
	if err != nil {
		t.Fatalf("server process keepalive: %v", err)
	}
	if result.Type != PacketKeepalive {
		t.Fatalf("expected keepalive, got %d", result.Type)
	}
}

func TestMaintenanceCleanup(t *testing.T) {
	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	// --- Test cleanupHandshakes ---
	// Inject a stale handshake.
	h.handshakesMutex.Lock()
	h.handshakes[999] = &handshake{
		localIndex: 999,
		created:    time.Now().Add(-(RejectAfterTime + time.Minute)),
	}
	h.handshakesMutex.Unlock()

	h.handshakesMutex.RLock()
	if len(h.handshakes) != 1 {
		t.Fatal("expected 1 handshake before cleanup")
	}
	h.handshakesMutex.RUnlock()

	h.Maintenance()

	h.handshakesMutex.RLock()
	if len(h.handshakes) != 0 {
		t.Fatal("stale handshake should have been cleaned up")
	}
	h.handshakesMutex.RUnlock()

	// --- Test cleanupSessions ---
	// Inject a stale session.
	staleTime := time.Now().Add(-(RejectAfterTime + time.Minute))
	var peerKey NoisePublicKey
	copy(peerKey[:], []byte("stale-session-peer-key-for-test!"))

	h.sessionsMutex.Lock()
	h.sessions[peerKey] = &session{
		peerKey:      peerKey,
		lastReceived: staleTime,
		lastSent:     staleTime,
	}
	h.sessionsMutex.Unlock()

	h.sessionsMutex.RLock()
	if _, exists := h.sessions[peerKey]; !exists {
		t.Fatal("session should exist before cleanup")
	}
	h.sessionsMutex.RUnlock()

	h.cleanupSessions()

	h.sessionsMutex.RLock()
	if _, exists := h.sessions[peerKey]; exists {
		t.Fatal("stale session should have been cleaned up")
	}
	h.sessionsMutex.RUnlock()
}

func TestCookieReplyFlow(t *testing.T) {
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	server, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler server: %v", err)
	}
	defer server.Close()

	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// Force server under load.
	server.loadMutex.Lock()
	server.underLoad = true
	server.loadMutex.Unlock()

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Client initiates handshake.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	// Server processes initiation — should return a cookie reply since under load
	// and MAC2 is zero.
	result, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server ProcessPacket: %v", err)
	}
	if result.Type != PacketCookieReply {
		t.Fatalf("expected cookie reply, got %d", result.Type)
	}

	// Client processes cookie reply.
	cookieResult, err := client.ProcessPacket(result.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client process cookie reply: %v", err)
	}
	if cookieResult.Type != PacketCookieReceived {
		t.Fatalf("expected PacketCookieReceived, got %d", cookieResult.Type)
	}

	// Clean up the old handshake so the client can start fresh.
	client.handshakesMutex.Lock()
	for k := range client.handshakes {
		delete(client.handshakes, k)
	}
	client.handshakesMutex.Unlock()

	// Client retries — cookie should now be stored, so MAC2 will be populated.
	retryPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("retry InitiateHandshake: %v", err)
	}

	// Verify MAC2 is now non-zero.
	if isZero(retryPkt[132:148]) {
		t.Fatal("MAC2 should be non-zero after cookie reply")
	}

	// Server processes the retry — should succeed.
	result2, err := server.ProcessPacket(retryPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server process retry: %v", err)
	}
	if result2.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response on retry, got %d", result2.Type)
	}
}

func TestIsZero(t *testing.T) {
	// Zero slice.
	if !isZero(make([]byte, 16)) {
		t.Fatal("expected isZero to return true for all-zero slice")
	}

	// Non-zero slice.
	nonZero := make([]byte, 16)
	nonZero[8] = 1
	if isZero(nonZero) {
		t.Fatal("expected isZero to return false for non-zero slice")
	}

	// Empty slice.
	if !isZero([]byte{}) {
		t.Fatal("expected isZero to return true for empty slice")
	}
}

func TestProcessPacketUnknownType(t *testing.T) {
	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	// Craft a packet with unknown message type 99.
	pkt := make([]byte, 32)
	binary_le_put_uint32(pkt[0:4], 99)

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	_, err = h.ProcessPacket(pkt, remoteAddr)
	if err == nil {
		t.Fatal("expected error for unknown message type")
	}

	// Packet too short.
	_, err = h.ProcessPacket([]byte{1, 2}, remoteAddr)
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestGetPeerInfo(t *testing.T) {
	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	// Unknown peer returns false.
	var unknownKey NoisePublicKey
	if _, ok := h.GetPeerInfo(unknownKey); ok {
		t.Fatal("expected false for unknown peer")
	}

	peer, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler peer: %v", err)
	}
	defer peer.Close()

	h.AddPeer(peer.PublicKey())

	info, ok := h.GetPeerInfo(peer.PublicKey())
	if !ok {
		t.Fatal("expected true for known peer")
	}
	if info.PublicKey != peer.PublicKey() {
		t.Fatal("public key mismatch")
	}
	if info.HasPSK {
		t.Fatal("expected no PSK")
	}
	if info.CreatedAt.IsZero() {
		t.Fatal("expected non-zero CreatedAt")
	}
}

func TestTimestampReplayProtection(t *testing.T) {
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	server, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler server: %v", err)
	}
	defer server.Close()

	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// First handshake should succeed.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}
	result, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if result.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got %d", result.Type)
	}

	// Replaying the exact same initiation packet should be rejected
	// because the timestamp is not strictly greater.
	_, err = server.ProcessPacket(initPkt, remoteAddr)
	if err == nil {
		t.Fatal("replayed handshake initiation should be rejected")
	}
	if !testing.Verbose() {
		t.Logf("replay correctly rejected: %v", err)
	}

	// A fresh handshake (new timestamp) should still succeed.
	// Clear client's pending handshakes first.
	client.handshakesMutex.Lock()
	for k := range client.handshakes {
		delete(client.handshakes, k)
	}
	client.handshakesMutex.Unlock()

	initPkt2, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("second InitiateHandshake: %v", err)
	}

	// Need to wait for cached time to advance to get a new timestamp.
	time.Sleep(150 * time.Millisecond)

	// Clear and retry with a fresh timestamp.
	client.handshakesMutex.Lock()
	for k := range client.handshakes {
		delete(client.handshakes, k)
	}
	client.handshakesMutex.Unlock()

	initPkt2, err = client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("third InitiateHandshake: %v", err)
	}
	result2, err := server.ProcessPacket(initPkt2, remoteAddr)
	if err != nil {
		t.Fatalf("fresh handshake after replay rejection: %v", err)
	}
	if result2.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got %d", result2.Type)
	}
}

func TestKeypairExpiration(t *testing.T) {
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	server, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler server: %v", err)
	}
	defer server.Close()

	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// Perform handshake.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	serverResult, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server ProcessPacket: %v", err)
	}

	_, err = client.ProcessPacket(serverResult.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client ProcessPacket: %v", err)
	}

	// Encryption should work with a fresh keypair.
	_, err = client.Encrypt([]byte("test"), server.PublicKey())
	if err != nil {
		t.Fatalf("Encrypt with fresh keypair: %v", err)
	}

	// Expire all keypairs by backdating their creation time.
	client.keypairsMutex.RLock()
	for _, kp := range client.keypairs {
		kp.created = time.Now().Add(-(RejectAfterTime + time.Minute))
	}
	client.keypairsMutex.RUnlock()

	// Encryption should now fail.
	_, err = client.Encrypt([]byte("test"), server.PublicKey())
	if err == nil {
		t.Fatal("Encrypt with expired keypair should fail")
	}

	// Also expire server-side keypairs and test decryption.
	server.keypairsMutex.RLock()
	for _, kp := range server.keypairs {
		kp.created = time.Now().Add(-(RejectAfterTime + time.Minute))
	}
	server.keypairsMutex.RUnlock()

	// Build a transport packet that references the expired keypair.
	kp := getFirstKeypair(t, server)
	nonce := make([]byte, 12)
	ciphertext := kp.receive.Seal(nil, nonce, []byte("test"), nil)
	pkt := make([]byte, messageTransportHeaderSize+len(ciphertext))
	binary_le_put_uint32(pkt[0:4], messageTransportType)
	binary_le_put_uint32(pkt[4:8], kp.localIndex)
	copy(pkt[messageTransportHeaderSize:], ciphertext)

	_, err = server.ProcessPacket(pkt, remoteAddr)
	if err == nil {
		t.Fatal("decrypt with expired keypair should fail")
	}
}

func TestPresharedKeyString(t *testing.T) {
	var psk NoisePresharedKey
	copy(psk[:], []byte("01234567890123456789012345678901"))

	s := psk.String()
	var psk2 NoisePresharedKey
	if err := psk2.UnmarshalText([]byte(s)); err != nil {
		t.Fatalf("PSK round-trip failed: %v", err)
	}
	if psk != psk2 {
		t.Fatal("PSK round-trip mismatch")
	}
}

func TestKeyEncoding(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pub := priv.PublicKey()

	// String round-trip for public key.
	s := pub.String()
	var pub2 NoisePublicKey
	if err := pub2.UnmarshalText([]byte(s)); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if pub != pub2 {
		t.Fatal("public key round-trip failed")
	}

	// MarshalText round-trip for private key.
	text, err := priv.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var priv2 NoisePrivateKey
	if err := priv2.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if priv != priv2 {
		t.Fatal("private key round-trip failed")
	}

	// Invalid base64.
	var pk NoisePublicKey
	if err := pk.UnmarshalText([]byte("not-base64!!!")); err == nil {
		t.Fatal("expected error for invalid base64")
	}

	// Wrong length.
	if err := pk.UnmarshalText([]byte("AAAA")); err == nil {
		t.Fatal("expected error for wrong length")
	}
}
