package wgnet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// buildHandshakeInitiation crafts a valid handshake initiation packet targeting
// the given server handler from a fresh client keypair. It returns the packet
// bytes and the client's private key (so the caller can complete the handshake).
func buildHandshakeInitiation(t *testing.T, server *Handler) ([]byte, NoisePrivateKey) {
	t.Helper()

	// Generate client keypair
	clientPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientPub := clientPriv.PublicKey()

	// Authorize client on the server
	server.AddPeer(clientPub)

	serverPub := server.PublicKey()

	// Start Noise IKpsk2 handshake
	var chainKey, hash [blake2s.Size]byte
	chainKey = initialChainKey
	hash = initialHash

	// Mix server public key
	mixHash(&hash, &hash, serverPub[:])

	// Generate ephemeral keypair
	ephPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	ephPub := ephPriv.PublicKey()

	// Mix ephemeral
	mixHash(&hash, &hash, ephPub[:])
	mixKey(&chainKey, &chainKey, ephPub[:])

	// DH: ephemeral -> server static
	tempSS, err := curve25519.X25519(ephPriv[:], serverPub[:])
	if err != nil {
		t.Fatalf("DH failed: %v", err)
	}

	var key [32]byte
	kdf2(&chainKey, &key, chainKey[:], tempSS)

	// Encrypt client static key
	cipher := createAEAD(key)
	encStatic := cipher.Seal(nil, zeroNonce[:], clientPub[:], hash[:])

	var staticField [48]byte
	copy(staticField[:], encStatic)
	mixHash(&hash, &hash, staticField[:])

	// Static-static DH
	tempSS, err = curve25519.X25519(clientPriv[:], serverPub[:])
	if err != nil {
		t.Fatalf("static DH failed: %v", err)
	}
	kdf2(&chainKey, &key, chainKey[:], tempSS)

	// Encrypt timestamp (TAI64N)
	var timestamp [12]byte
	n := now()
	secs := uint64(n.Unix()) + 4611686018427387914
	binary.BigEndian.PutUint64(timestamp[0:8], secs)
	binary.BigEndian.PutUint32(timestamp[8:12], uint32(n.Nanosecond()))

	cipher = createAEAD(key)
	encTimestamp := cipher.Seal(nil, zeroNonce[:], timestamp[:], hash[:])

	var timestampField [28]byte
	copy(timestampField[:], encTimestamp)

	// Build the wire-format message
	var senderIdx uint32 = 42

	pkt := make([]byte, MessageInitiationSize)
	binary_le_put_uint32(pkt[0:4], MessageInitiationType)
	binary_le_put_uint32(pkt[4:8], senderIdx)
	copy(pkt[8:40], ephPub[:])
	copy(pkt[40:88], staticField[:])
	copy(pkt[88:116], timestampField[:])

	// Compute MAC1
	mac1Key := calculateMAC1Key(serverPub)
	mac1Hasher, _ := blake2s.New128(mac1Key[:])
	mac1Hasher.Write(pkt[:116])
	mac1Hasher.Sum(pkt[116:116:132])

	// MAC2 = zeros (no cookie)

	return pkt, clientPriv
}

func TestMultiHandlerMAC1Routing(t *testing.T) {
	// Create two server handlers with distinct keys
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler 1: %v", err)
	}
	defer h1.Close()

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler 2: %v", err)
	}
	defer h2.Close()

	mh, err := NewMultiHandler(h1, h2)
	if err != nil {
		t.Fatalf("create multi handler: %v", err)
	}
	defer mh.Close()

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Build a handshake targeting h1
	pkt1, _ := buildHandshakeInitiation(t, h1)
	result1, err := mh.ProcessPacket(pkt1, remoteAddr)
	if err != nil {
		t.Fatalf("process packet for h1: %v", err)
	}
	if result1.Handler != h1 {
		t.Fatalf("expected handler h1, got different handler")
	}
	if result1.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got %d", result1.Type)
	}
	pk1 := h1.PublicKey()
	t.Logf("handshake correctly routed to handler 1 (pubkey %x...)", pk1[:4])

	// Build a handshake targeting h2
	pkt2, _ := buildHandshakeInitiation(t, h2)
	result2, err := mh.ProcessPacket(pkt2, remoteAddr)
	if err != nil {
		t.Fatalf("process packet for h2: %v", err)
	}
	if result2.Handler != h2 {
		t.Fatalf("expected handler h2, got different handler")
	}
	pk2 := h2.PublicKey()
	t.Logf("handshake correctly routed to handler 2 (pubkey %x...)", pk2[:4])
}

func TestMultiHandlerTransportRouting(t *testing.T) {
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler 1: %v", err)
	}
	defer h1.Close()

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler 2: %v", err)
	}
	defer h2.Close()

	mh, err := NewMultiHandler(h1, h2)
	if err != nil {
		t.Fatalf("create multi handler: %v", err)
	}
	defer mh.Close()

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Establish a session on h1 via a real handshake
	pkt, _ := buildHandshakeInitiation(t, h1)
	result, err := mh.ProcessPacket(pkt, remoteAddr)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// The server now has a keypair. To test transport routing, we need to send
	// a transport packet that h1 can decrypt. Since this handler doesn't
	// support client-side handshake response processing, we inject a synthetic
	// keypair to act as the "client" that can produce packets h1 will accept.

	// Find h1's keypair to get the AEAD ciphers (same package = internal access)
	h1.keypairsMutex.RLock()
	var serverKeypair *Keypair
	for _, kp := range h1.keypairs {
		serverKeypair = kp
		break
	}
	h1.keypairsMutex.RUnlock()

	if serverKeypair == nil {
		t.Fatal("server has no keypair after handshake")
	}

	// Build a transport packet that h1 can decrypt.
	// The server's "receive" cipher corresponds to what the client's "send" cipher would be.
	// We use it directly to produce a valid ciphertext.
	testData := []byte("hello from client")
	var counter uint64 = 1
	var nonce [12]byte
	binary_le_put_uint64(nonce[4:], counter)
	ciphertext := serverKeypair.receive.Seal(nil, nonce[:], testData, nil)

	// Build transport packet: [type:4][receiver:4][counter:8][ciphertext]
	transportPkt := make([]byte, 16+len(ciphertext))
	binary_le_put_uint32(transportPkt[0:4], MessageTransportType)
	binary_le_put_uint32(transportPkt[4:8], serverKeypair.localIndex)
	binary_le_put_uint64(transportPkt[8:16], counter)
	copy(transportPkt[16:], ciphertext)

	// Route through MultiHandler — should go to h1
	transportResult, err := mh.ProcessPacket(transportPkt, remoteAddr)
	if err != nil {
		t.Fatalf("route transport: %v", err)
	}
	if transportResult.Handler != h1 {
		t.Fatalf("expected transport routed to h1")
	}
	if string(transportResult.Data) != string(testData) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", transportResult.Data, testData)
	}

	_ = result // handshake response not needed for this test
	t.Log("transport packet correctly routed to handler 1")
}

func TestMultiHandlerUnknownIdentity(t *testing.T) {
	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	defer h1.Close()

	mh, err := NewMultiHandler(h1)
	if err != nil {
		t.Fatalf("create multi handler: %v", err)
	}
	defer mh.Close()

	// Create a handshake for a handler NOT in the MultiHandler
	hOther, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create other handler: %v", err)
	}
	defer hOther.Close()

	pkt, _ := buildHandshakeInitiation(t, hOther)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	_, err = mh.ProcessPacket(pkt, remoteAddr)
	if err == nil {
		t.Fatal("expected error for unknown identity, got nil")
	}
	t.Logf("correctly rejected unknown identity: %v", err)
}

func TestMultiHandlerDuplicateKey(t *testing.T) {
	privKey, _ := GeneratePrivateKey()
	h1, _ := NewHandler(Config{PrivateKey: privKey})
	h2, _ := NewHandler(Config{PrivateKey: privKey})
	defer h1.Close()
	defer h2.Close()

	_, err := NewMultiHandler(h1, h2)
	if err == nil {
		t.Fatal("expected error for duplicate public keys")
	}
	t.Logf("correctly rejected duplicate keys: %v", err)
}

func TestMultiHandlerAddRemove(t *testing.T) {
	h1, _ := NewHandler(Config{})
	h2, _ := NewHandler(Config{})
	defer h1.Close()
	defer h2.Close()

	mh, err := NewMultiHandler(h1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Add h2
	if err := mh.AddHandler(h2); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(mh.Handlers()) != 2 {
		t.Fatalf("expected 2 handlers, got %d", len(mh.Handlers()))
	}

	// Adding duplicate should fail
	if err := mh.AddHandler(h1); err == nil {
		t.Fatal("expected error for duplicate add")
	}

	// Lookup
	found := mh.Handler(h2.PublicKey())
	if found != h2 {
		t.Fatal("handler lookup failed")
	}

	// Remove
	removed := mh.RemoveHandler(h2.PublicKey())
	if removed != h2 {
		t.Fatal("remove returned wrong handler")
	}
	if len(mh.Handlers()) != 1 {
		t.Fatalf("expected 1 handler after remove, got %d", len(mh.Handlers()))
	}

	// Remove non-existent
	if mh.RemoveHandler(h2.PublicKey()) != nil {
		t.Fatal("expected nil for non-existent remove")
	}
}

func TestMultiHandlerRouteByReceiverIndex(t *testing.T) {
	// Create server handlers.
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
	defer mh.Close()

	// Create a client that will handshake with h1.
	client, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler client: %v", err)
	}
	defer client.Close()

	client.AddPeer(h1.PublicKey())
	h1.AddPeer(client.PublicKey())

	// Client initiates handshake.
	initPkt, err := client.InitiateHandshake(h1.PublicKey())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// MultiHandler processes the initiation (type 1 — routed by MAC1).
	result, err := mh.ProcessPacket(initPkt, remoteAddr)
	if err != nil {
		t.Fatalf("process initiation: %v", err)
	}
	if result.Handler != h1 {
		t.Fatal("initiation should route to h1")
	}

	// The response is a type-2 packet. Now we wrap it in a MultiHandler
	// on the client side to test type-2 routing by receiver index.
	clientMH, err := NewMultiHandler(client)
	if err != nil {
		t.Fatalf("NewMultiHandler client: %v", err)
	}
	defer clientMH.Close()

	// Process the type-2 response through the client's MultiHandler.
	clientResult, err := clientMH.ProcessPacket(result.Response, remoteAddr)
	if err != nil {
		t.Fatalf("client process type-2 response: %v", err)
	}
	if clientResult.Handler != client {
		t.Fatal("type-2 should route to client handler")
	}
	if clientResult.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got %d", clientResult.Type)
	}

	// Verify session is established.
	if !client.HasSession(h1.PublicKey()) {
		t.Fatal("client should have session with h1")
	}
}

func TestMultiHandlerMaintenance(t *testing.T) {
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
	defer mh.Close()

	// Inject stale handshakes into both handlers.
	staleTime := time.Now().Add(-(RejectAfterTime + time.Minute))
	h1.handshakesMutex.Lock()
	h1.handshakes[111] = &Handshake{localIndex: 111, created: staleTime}
	h1.handshakesMutex.Unlock()

	h2.handshakesMutex.Lock()
	h2.handshakes[222] = &Handshake{localIndex: 222, created: staleTime}
	h2.handshakesMutex.Unlock()

	// Run Maintenance on the MultiHandler.
	mh.Maintenance()

	// Verify stale handshakes are cleaned up.
	h1.handshakesMutex.RLock()
	if len(h1.handshakes) != 0 {
		t.Fatal("h1 stale handshake should be cleaned up")
	}
	h1.handshakesMutex.RUnlock()

	h2.handshakesMutex.RLock()
	if len(h2.handshakes) != 0 {
		t.Fatal("h2 stale handshake should be cleaned up")
	}
	h2.handshakesMutex.RUnlock()
}

func TestMultiHandlerEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wireguard-loop-go does not support Windows")
	}

	loopBin := findLoopBinary(t)

	// Channel for async unknown-peer results
	type asyncResult struct {
		result *PacketResult
		addr   net.Addr
	}
	asyncCh := make(chan asyncResult, 4)

	// Create two server identities with async unknown-peer callbacks
	makeCallback := func(h *Handler) UnknownPeerFunc {
		return func(pk NoisePublicKey, addr *net.UDPAddr, packet []byte) {
			pkt := make([]byte, len(packet))
			copy(pkt, packet)
			go func() {
				res, err := h.AcceptUnknownPeer(pk, pkt, addr)
				if err != nil {
					t.Logf("AcceptUnknownPeer error: %v", err)
					return
				}
				asyncCh <- asyncResult{result: res, addr: addr}
			}()
		}
	}

	h1, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler 1: %v", err)
	}
	defer h1.Close()
	h1.onUnknownPeer = makeCallback(h1)

	h2, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler 2: %v", err)
	}
	defer h2.Close()
	h2.onUnknownPeer = makeCallback(h2)

	mh, err := NewMultiHandler(h1, h2)
	if err != nil {
		t.Fatalf("create multi handler: %v", err)
	}
	defer mh.Close()

	// Open one shared UDP socket
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer udpConn.Close()
	ourAddr := udpConn.LocalAddr().(*net.UDPAddr)

	// Start two wireguard-loop-go instances, each targeting a different identity
	type loopInstance struct {
		name    string
		handler *Handler
		privKey NoisePrivateKey
		pubKey  NoisePublicKey
		cmd     *exec.Cmd
	}

	instances := make([]loopInstance, 2)
	for i, h := range []*Handler{h1, h2} {
		loopPriv, err := GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate loop key %d: %v", i, err)
		}

		ifaceName := fmt.Sprintf("wgmulti%d_%d", os.Getpid(), i)
		cmd := exec.Command(loopBin, "-f", ifaceName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			t.Fatalf("start loop %d: %v", i, err)
		}

		instances[i] = loopInstance{
			name:    ifaceName,
			handler: h,
			privKey: loopPriv,
			pubKey:  loopPriv.PublicKey(),
			cmd:     cmd,
		}
	}

	// Cleanup all processes
	defer func() {
		for _, inst := range instances {
			inst.cmd.Process.Kill()
			inst.cmd.Wait()
		}
	}()

	// Configure each instance
	for i, inst := range instances {
		sockPath := uapiSocketPath(inst.name)
		waitForSocket(t, sockPath, 5*time.Second)

		serverPub := inst.handler.PublicKey()
		config := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=0.0.0.0/0\nendpoint=%s\npersistent_keepalive_interval=1\n",
			hex.EncodeToString(inst.privKey[:]),
			hex.EncodeToString(serverPub[:]),
			ourAddr.String(),
		)
		configureViaUAPI(t, sockPath, config)
		t.Logf("loop instance %d configured (targeting handler %x...)", i, serverPub[:4])
	}

	// sendResponse sends async unknown-peer handshake responses
	sendAsyncResponses := func() {
		for {
			select {
			case ar := <-asyncCh:
				if ar.result != nil && ar.result.Response != nil {
					if _, err := udpConn.WriteTo(ar.result.Response, ar.addr); err != nil {
						t.Logf("send async response: %v", err)
					}
				}
			default:
				return
			}
		}
	}

	// Process handshakes and data from both instances
	handshakesDone := map[int]bool{}
	dataDone := map[int]bool{}
	buf := make([]byte, 2048)

	for len(handshakesDone) < 2 || len(dataDone) < 2 {
		// Drain any async handshake responses
		sendAsyncResponses()

		udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, remoteAddr, err := udpConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read packet: %v (handshakes=%d, data=%d)", err, len(handshakesDone), len(dataDone))
		}

		result, err := mh.ProcessPacket(buf[:n], remoteAddr.(*net.UDPAddr))
		if err != nil {
			t.Logf("process error (may be expected during negotiation): %v", err)
			// Drain async responses that may have been triggered by the callback
			time.Sleep(10 * time.Millisecond)
			sendAsyncResponses()
			continue
		}

		// Identify which instance this belongs to
		idx := -1
		for i, inst := range instances {
			if result.Handler == inst.handler {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatal("result handler doesn't match any instance")
		}

		switch result.Type {
		case PacketHandshakeResponse:
			if _, err := udpConn.WriteTo(result.Response, remoteAddr); err != nil {
				t.Fatalf("send response %d: %v", idx, err)
			}
			handshakesDone[idx] = true
			t.Logf("instance %d: handshake completed", idx)

		case PacketKeepalive:
			t.Logf("instance %d: keepalive received", idx)
			// Send a test packet back so we get data echo
			if !dataDone[idx] {
				testPkt := makeIPv4Packet(
					net.IPv4(10, 0, 0, 1).To4(),
					net.IPv4(10, 0, 0, 2).To4(),
					[]byte(fmt.Sprintf("hello from identity %d", idx)),
				)
				encrypted, err := instances[idx].handler.Encrypt(testPkt, instances[idx].pubKey)
				if err != nil {
					t.Fatalf("encrypt for instance %d: %v", idx, err)
				}
				if _, err := udpConn.WriteTo(encrypted, remoteAddr); err != nil {
					t.Fatalf("send data %d: %v", idx, err)
				}
			}

		case PacketTransportData:
			dataDone[idx] = true
			t.Logf("instance %d: data received (%d bytes)", idx, len(result.Data))
		}
	}

	t.Log("multi-identity end-to-end test passed: both handlers completed handshake + data")
}
