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
