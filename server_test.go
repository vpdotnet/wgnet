package wgnet

import (
	"net"
	"testing"
	"time"
)

func TestServerConfigValidation(t *testing.T) {
	noop := func([]byte, NoisePublicKey, *Handler) {}

	// Neither handler nor multi handler.
	_, err := NewServer(ServerConfig{OnPacket: noop})
	if err == nil {
		t.Fatal("expected error with no handler")
	}

	h, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()

	mh, err := NewMultiHandler(h)
	if err != nil {
		t.Fatalf("NewMultiHandler: %v", err)
	}

	// Both handler and multi handler.
	_, err = NewServer(ServerConfig{Handler: h, MultiHandler: mh, OnPacket: noop})
	if err == nil {
		t.Fatal("expected error with both handlers")
	}

	// Missing OnPacket.
	_, err = NewServer(ServerConfig{Handler: h})
	if err == nil {
		t.Fatal("expected error with no OnPacket")
	}
}

func TestServerSingleHandler(t *testing.T) {
	handler, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer handler.Close()

	packetCh := make(chan []byte, 1)
	connectedCh := make(chan NoisePublicKey, 1)

	srv, err := NewServer(ServerConfig{
		Handler: handler,
		OnPacket: func(data []byte, peerKey NoisePublicKey, h *Handler) {
			d := make([]byte, len(data))
			copy(d, data)
			packetCh <- d
		},
		OnPeerConnected: func(peerKey NoisePublicKey, h *Handler) {
			connectedCh <- peerKey
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	go srv.Serve(conn)
	defer srv.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket client: %v", err)
	}
	defer client.Close()

	// Perform handshake.
	initPkt, clientPrivKey := buildHandshakeInitiation(t, handler)
	clientPubKey := clientPrivKey.PublicKey()

	if _, err := client.WriteTo(initPkt, conn.LocalAddr()); err != nil {
		t.Fatalf("send initiation: %v", err)
	}

	buf := make([]byte, 256)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != MessageResponseSize {
		t.Fatalf("response size: got %d, want %d", n, MessageResponseSize)
	}

	// Verify OnPeerConnected fired.
	select {
	case key := <-connectedCh:
		if key != clientPubKey {
			t.Fatal("OnPeerConnected: wrong key")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnPeerConnected not called")
	}

	// Verify PeerAddr is tracked.
	if addr := srv.PeerAddr(clientPubKey); addr == nil {
		t.Fatal("PeerAddr returned nil after handshake")
	}

	// Send a transport packet using internal keypair access.
	kp := getFirstKeypair(t, handler)

	plaintext := []byte("hello from client")
	nonce := make([]byte, 12)
	ciphertext := kp.receive.Seal(nil, nonce, plaintext, nil)

	pkt := make([]byte, MessageTransportHeaderSize+len(ciphertext))
	binary_le_put_uint32(pkt[0:4], MessageTransportType)
	binary_le_put_uint32(pkt[4:8], kp.localIndex)
	copy(pkt[MessageTransportHeaderSize:], ciphertext)

	if _, err := client.WriteTo(pkt, conn.LocalAddr()); err != nil {
		t.Fatalf("send transport: %v", err)
	}

	select {
	case data := <-packetCh:
		if string(data) != string(plaintext) {
			t.Fatalf("OnPacket data: got %q, want %q", data, plaintext)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnPacket not called")
	}
}

func TestServerMultiHandler(t *testing.T) {
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h1: %v", err)
	}
	defer h1.Close()

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h2: %v", err)
	}
	defer h2.Close()

	mh, err := NewMultiHandler(h1, h2)
	if err != nil {
		t.Fatalf("NewMultiHandler: %v", err)
	}

	type packetInfo struct {
		data    []byte
		handler *Handler
	}
	packetCh := make(chan packetInfo, 2)

	srv, err := NewServer(ServerConfig{
		MultiHandler: mh,
		OnPacket: func(data []byte, peerKey NoisePublicKey, h *Handler) {
			d := make([]byte, len(data))
			copy(d, data)
			packetCh <- packetInfo{d, h}
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	go srv.Serve(conn)
	defer srv.Close()

	// Helper: handshake + send transport targeting a specific handler.
	sendTransport := func(t *testing.T, targetHandler *Handler, payload string) {
		t.Helper()

		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer c.Close()

		initPkt, _ := buildHandshakeInitiation(t, targetHandler)
		if _, err := c.WriteTo(initPkt, conn.LocalAddr()); err != nil {
			t.Fatalf("send initiation: %v", err)
		}

		buf := make([]byte, 256)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if n != MessageResponseSize {
			t.Fatalf("response size: got %d, want %d", n, MessageResponseSize)
		}

		kp := getFirstKeypair(t, targetHandler)

		nonce := make([]byte, 12)
		ciphertext := kp.receive.Seal(nil, nonce, []byte(payload), nil)

		pkt := make([]byte, MessageTransportHeaderSize+len(ciphertext))
		binary_le_put_uint32(pkt[0:4], MessageTransportType)
		binary_le_put_uint32(pkt[4:8], kp.localIndex)
		copy(pkt[MessageTransportHeaderSize:], ciphertext)

		if _, err := c.WriteTo(pkt, conn.LocalAddr()); err != nil {
			t.Fatalf("send transport: %v", err)
		}
	}

	// Handshake + transport targeting h1.
	sendTransport(t, h1, "payload-h1")
	select {
	case info := <-packetCh:
		if string(info.data) != "payload-h1" {
			t.Fatalf("h1 data: got %q", info.data)
		}
		if info.handler != h1 {
			t.Fatal("wrong handler for h1 packet")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for h1 packet")
	}

	// Handshake + transport targeting h2.
	sendTransport(t, h2, "payload-h2")
	select {
	case info := <-packetCh:
		if string(info.data) != "payload-h2" {
			t.Fatalf("h2 data: got %q", info.data)
		}
		if info.handler != h2 {
			t.Fatal("wrong handler for h2 packet")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for h2 packet")
	}
}

func TestServerSend(t *testing.T) {
	handler, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer handler.Close()

	srv, err := NewServer(ServerConfig{
		Handler:  handler,
		OnPacket: func([]byte, NoisePublicKey, *Handler) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	go srv.Serve(conn)
	defer srv.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket client: %v", err)
	}
	defer client.Close()

	// Establish session.
	initPkt, clientPrivKey := buildHandshakeInitiation(t, handler)
	clientPubKey := clientPrivKey.PublicKey()

	if _, err := client.WriteTo(initPkt, conn.LocalAddr()); err != nil {
		t.Fatalf("send initiation: %v", err)
	}

	buf := make([]byte, 256)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != MessageResponseSize {
		t.Fatalf("response size: got %d, want %d", n, MessageResponseSize)
	}

	// Wait for the server to fully process the handshake.
	time.Sleep(50 * time.Millisecond)

	// Send from server to client.
	payload := []byte("hello from server")
	if err := srv.Send(payload, clientPubKey); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Read the encrypted packet on the client socket.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read transport: %v", err)
	}
	if n < MessageTransportHeaderSize {
		t.Fatalf("packet too short: %d", n)
	}

	msgType := binary_le_uint32(buf[0:4])
	if msgType != MessageTransportType {
		t.Fatalf("message type: got %d, want %d", msgType, MessageTransportType)
	}

	// Decrypt using the server's send cipher to verify the payload.
	kp := getFirstKeypair(t, handler)
	counter := binary_le_uint64(buf[8:16])
	var nonce [12]byte
	binary_le_put_uint64(nonce[4:], counter)
	decrypted, err := kp.send.Open(nil, nonce[:], buf[MessageTransportHeaderSize:n], nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Fatalf("payload: got %q, want %q", decrypted, payload)
	}
}

func TestServerClose(t *testing.T) {
	handler, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer handler.Close()

	srv, err := NewServer(ServerConfig{
		Handler:  handler,
		OnPacket: func([]byte, NoisePublicKey, *Handler) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	serveDone := make(chan struct{})
	go func() {
		srv.Serve(conn)
		close(serveDone)
	}()

	// Give goroutines time to start.
	time.Sleep(50 * time.Millisecond)

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}

	// Calling Close again should not panic.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestInitiateHandshake(t *testing.T) {
	// Create a client handler and a server handler.
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

	// Authorize each other.
	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// Build initiation from client to server.
	pkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	// Verify packet size.
	if len(pkt) != MessageInitiationSize {
		t.Fatalf("packet size: got %d, want %d", len(pkt), MessageInitiationSize)
	}

	// Verify handshake state is stored.
	client.handshakesMutex.RLock()
	hsCount := len(client.handshakes)
	client.handshakesMutex.RUnlock()
	if hsCount != 1 {
		t.Fatalf("pending handshakes: got %d, want 1", hsCount)
	}

	// Verify the server can process the initiation.
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	result, err := server.ProcessPacket(pkt, remoteAddr)
	if err != nil {
		t.Fatalf("server ProcessPacket: %v", err)
	}
	if result.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got %d", result.Type)
	}
	if result.PeerKey != client.PublicKey() {
		t.Fatal("response PeerKey mismatch")
	}
}

func TestClientHandshakeFlow(t *testing.T) {
	// Create client and server handlers.
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

	// Authorize each other.
	client.AddPeer(server.PublicKey())
	server.AddPeer(client.PublicKey())

	// Client initiates handshake.
	initPkt, err := client.InitiateHandshake(server.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	// Server processes initiation → produces response.
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	serverResult, err := server.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("server process initiation: %v", err)
	}
	if serverResult.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got %d", serverResult.Type)
	}

	// Client processes response → produces keepalive.
	clientResult, err := client.ProcessPacket(serverResult.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client process response: %v", err)
	}
	if clientResult.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response (keepalive), got %d", clientResult.Type)
	}
	if clientResult.PeerKey != server.PublicKey() {
		t.Fatal("client result PeerKey mismatch")
	}

	// Verify sessions exist on both sides.
	if !client.HasSession(server.PublicKey()) {
		t.Fatal("client has no session with server")
	}
	if !server.HasSession(client.PublicKey()) {
		t.Fatal("server has no session with client")
	}

	// Server should be able to decrypt the keepalive.
	keepaliveResult, err := server.ProcessPacket(clientResult.Response, remoteAddr)
	if err != nil {
		t.Fatalf("server process keepalive: %v", err)
	}
	if keepaliveResult.Type != PacketKeepalive {
		t.Fatalf("expected keepalive, got %d", keepaliveResult.Type)
	}

	// Bidirectional data exchange: client → server.
	payload1 := []byte("hello from client")
	encrypted1, err := client.Encrypt(payload1, server.PublicKey())
	if err != nil {
		t.Fatalf("client Encrypt: %v", err)
	}
	decrypted1, err := server.ProcessPacket(encrypted1, remoteAddr)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if string(decrypted1.Data) != string(payload1) {
		t.Fatalf("client→server: got %q, want %q", decrypted1.Data, payload1)
	}

	// Bidirectional data exchange: server → client.
	payload2 := []byte("hello from server")
	encrypted2, err := server.Encrypt(payload2, client.PublicKey())
	if err != nil {
		t.Fatalf("server Encrypt: %v", err)
	}
	decrypted2, err := client.ProcessPacket(encrypted2, remoteAddr)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if string(decrypted2.Data) != string(payload2) {
		t.Fatalf("server→client: got %q, want %q", decrypted2.Data, payload2)
	}
}

func TestServerConnect(t *testing.T) {
	// Create two handlers.
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h1: %v", err)
	}
	defer h1.Close()

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h2: %v", err)
	}
	defer h2.Close()

	// Authorize each other.
	h1.AddPeer(h2.PublicKey())
	h2.AddPeer(h1.PublicKey())

	connected1 := make(chan NoisePublicKey, 1)
	connected2 := make(chan NoisePublicKey, 1)
	packet1 := make(chan []byte, 1)
	packet2 := make(chan []byte, 1)

	srv1, err := NewServer(ServerConfig{
		Handler: h1,
		OnPacket: func(data []byte, peerKey NoisePublicKey, h *Handler) {
			d := make([]byte, len(data))
			copy(d, data)
			packet1 <- d
		},
		OnPeerConnected: func(peerKey NoisePublicKey, h *Handler) {
			connected1 <- peerKey
		},
	})
	if err != nil {
		t.Fatalf("NewServer srv1: %v", err)
	}

	srv2, err := NewServer(ServerConfig{
		Handler: h2,
		OnPacket: func(data []byte, peerKey NoisePublicKey, h *Handler) {
			d := make([]byte, len(data))
			copy(d, data)
			packet2 <- d
		},
		OnPeerConnected: func(peerKey NoisePublicKey, h *Handler) {
			connected2 <- peerKey
		},
	})
	if err != nil {
		t.Fatalf("NewServer srv2: %v", err)
	}

	conn1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket conn1: %v", err)
	}
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket conn2: %v", err)
	}
	defer conn2.Close()

	go srv1.Serve(conn1)
	defer srv1.Close()

	go srv2.Serve(conn2)
	defer srv2.Close()

	// Give servers time to start.
	time.Sleep(50 * time.Millisecond)

	// srv1 connects to srv2.
	addr2 := conn2.LocalAddr().(*net.UDPAddr)
	if err := srv1.Connect(h2.PublicKey(), addr2); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Verify OnPeerConnected fires on both sides.
	select {
	case key := <-connected1:
		if key != h2.PublicKey() {
			t.Fatal("srv1 connected to wrong peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("srv1 OnPeerConnected not called")
	}

	select {
	case key := <-connected2:
		if key != h1.PublicKey() {
			t.Fatal("srv2 connected to wrong peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("srv2 OnPeerConnected not called")
	}

	// Exchange data: srv1 → srv2.
	payload1 := []byte("data from srv1")
	if err := srv1.Send(payload1, h2.PublicKey()); err != nil {
		t.Fatalf("srv1 Send: %v", err)
	}
	select {
	case data := <-packet2:
		if string(data) != string(payload1) {
			t.Fatalf("srv2 received: got %q, want %q", data, payload1)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("srv2 did not receive data")
	}

	// Exchange data: srv2 → srv1.
	payload2 := []byte("data from srv2")
	if err := srv2.Send(payload2, h1.PublicKey()); err != nil {
		t.Fatalf("srv2 Send: %v", err)
	}
	select {
	case data := <-packet1:
		if string(data) != string(payload2) {
			t.Fatalf("srv1 received: got %q, want %q", data, payload2)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("srv1 did not receive data")
	}
}

func TestServerConnectWith(t *testing.T) {
	// Create two handler identities for the server.
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h1: %v", err)
	}
	defer h1.Close()

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h2: %v", err)
	}
	defer h2.Close()

	// Create a remote peer handler.
	peer, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler peer: %v", err)
	}
	defer peer.Close()

	// Authorize peer on h2 (not h1).
	h2.AddPeer(peer.PublicKey())
	peer.AddPeer(h2.PublicKey())

	mh, err := NewMultiHandler(h1, h2)
	if err != nil {
		t.Fatalf("NewMultiHandler: %v", err)
	}

	connectedCh := make(chan NoisePublicKey, 1)
	srv, err := NewServer(ServerConfig{
		MultiHandler: mh,
		OnPacket:     func([]byte, NoisePublicKey, *Handler) {},
		OnPeerConnected: func(peerKey NoisePublicKey, h *Handler) {
			connectedCh <- peerKey
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	// Peer server to receive the initiation.
	peerSrv, err := NewServer(ServerConfig{
		Handler:  peer,
		OnPacket: func([]byte, NoisePublicKey, *Handler) {},
		OnPeerConnected: func(peerKey NoisePublicKey, h *Handler) {
		},
	})
	if err != nil {
		t.Fatalf("NewServer peer: %v", err)
	}

	peerConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket peer: %v", err)
	}
	defer peerConn.Close()

	go srv.Serve(conn)
	defer srv.Close()

	go peerSrv.Serve(peerConn)
	defer peerSrv.Close()

	time.Sleep(50 * time.Millisecond)

	// Connect using multi-handler mode should fail with Connect.
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	err = srv.Connect(peer.PublicKey(), peerAddr)
	if err == nil {
		t.Fatal("Connect should fail in multi-handler mode")
	}

	// ConnectWith should succeed.
	err = srv.ConnectWith(peer.PublicKey(), peerAddr, h2)
	if err != nil {
		t.Fatalf("ConnectWith: %v", err)
	}

	// Wait for the handshake to complete.
	select {
	case key := <-connectedCh:
		if key != peer.PublicKey() {
			t.Fatal("connected to wrong peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnPeerConnected not called")
	}
}

func TestServerSendMultiHandler(t *testing.T) {
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h1: %v", err)
	}
	defer h1.Close()

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler h2: %v", err)
	}
	defer h2.Close()

	mh, err := NewMultiHandler(h1, h2)
	if err != nil {
		t.Fatalf("NewMultiHandler: %v", err)
	}

	packetCh := make(chan []byte, 1)
	connectedCh := make(chan NoisePublicKey, 1)
	srv, err := NewServer(ServerConfig{
		MultiHandler: mh,
		OnPacket: func(data []byte, peerKey NoisePublicKey, h *Handler) {
			d := make([]byte, len(data))
			copy(d, data)
			packetCh <- d
		},
		OnPeerConnected: func(peerKey NoisePublicKey, h *Handler) {
			connectedCh <- peerKey
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	go srv.Serve(conn)
	defer srv.Close()

	// Create a client and handshake targeting h1.
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket client: %v", err)
	}
	defer client.Close()

	initPkt, clientPrivKey := buildHandshakeInitiation(t, h1)
	clientPubKey := clientPrivKey.PublicKey()

	if _, err := client.WriteTo(initPkt, conn.LocalAddr()); err != nil {
		t.Fatalf("send initiation: %v", err)
	}

	buf := make([]byte, 256)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n != MessageResponseSize {
		t.Fatalf("response size: got %d, want %d", n, MessageResponseSize)
	}

	select {
	case <-connectedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("OnPeerConnected not called")
	}

	// Wait for server to process.
	time.Sleep(50 * time.Millisecond)

	// Send should auto-select h1 for this peer.
	payload := []byte("auto-select test")
	if err := srv.Send(payload, clientPubKey); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Read and decrypt on client side.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read transport: %v", err)
	}
	if n < MessageTransportHeaderSize {
		t.Fatalf("packet too short: %d", n)
	}

	msgType := binary_le_uint32(buf[0:4])
	if msgType != MessageTransportType {
		t.Fatalf("message type: got %d, want %d", msgType, MessageTransportType)
	}

	// Send for unknown peer should fail.
	var unknownKey NoisePublicKey
	copy(unknownKey[:], []byte("unknown-peer-key-for-testing!!!!"))
	if err := srv.Send([]byte("test"), unknownKey); err == nil {
		t.Fatal("Send to unknown peer should fail in multi-handler mode")
	}
}

// getFirstKeypair returns the first keypair from a handler's internal map.
// Used by tests to craft synthetic transport packets.
func getFirstKeypair(t *testing.T, h *Handler) *Keypair {
	t.Helper()
	h.keypairsMutex.RLock()
	defer h.keypairsMutex.RUnlock()
	for _, kp := range h.keypairs {
		return kp
	}
	t.Fatal("handler has no keypairs")
	return nil
}
