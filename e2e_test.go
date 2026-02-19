package wgnet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// findLoopBinary returns the path to the wireguard-loop-go binary.
// It checks the WIREGUARD_LOOP_BIN environment variable first, then
// looks in common build locations. The test is skipped if not found.
func findLoopBinary(t *testing.T) string {
	t.Helper()

	if bin := os.Getenv("WIREGUARD_LOOP_BIN"); bin != "" {
		if _, err := os.Stat(bin); err == nil {
			return bin
		}
		t.Fatalf("WIREGUARD_LOOP_BIN=%q does not exist", bin)
	}

	t.Skip("WIREGUARD_LOOP_BIN not set; skipping end-to-end test")
	return ""
}

// configureViaUAPI connects to the wireguard-loop-go UAPI unix socket and
// sends a configuration. The config should be a newline-separated list of
// key=value pairs (without the leading "set=1\n" or trailing "\n").
func configureViaUAPI(t *testing.T, socketPath, config string) {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial UAPI socket %s: %v", socketPath, err)
	}
	defer conn.Close()

	// The UAPI protocol: send "set=1\n" followed by key=value lines, ending with "\n"
	payload := "set=1\n" + config + "\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write UAPI config: %v", err)
	}

	// Read response — expect "errno=0\n\n" on success
	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read UAPI response: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "errno=0") {
		t.Fatalf("UAPI config failed: %s", resp)
	}
}

// makeIPv4Packet crafts a minimal valid IPv4 packet with the given source/destination
// addresses and payload. It builds a 20-byte header (no options) with correct
// total length and header checksum.
func makeIPv4Packet(src, dst net.IP, payload []byte) []byte {
	src = src.To4()
	dst = dst.To4()

	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)

	// Version (4) + IHL (5 = 20 bytes) = 0x45
	pkt[0] = 0x45
	// DSCP/ECN
	pkt[1] = 0
	// Total length
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// Identification
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	// Flags + Fragment offset (Don't Fragment)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	// TTL
	pkt[8] = 64
	// Protocol (UDP = 17)
	pkt[9] = 17
	// Header checksum (initially 0, computed below)
	pkt[10] = 0
	pkt[11] = 0
	// Source IP
	copy(pkt[12:16], src)
	// Destination IP
	copy(pkt[16:20], dst)
	// Payload
	copy(pkt[20:], payload)

	// Compute header checksum over the 20-byte header
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	return pkt
}

// uapiSocketPath returns the expected UAPI socket path for a given interface name.
func uapiSocketPath(ifaceName string) string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "wireguard-loop", ifaceName+".sock")
	}
	return filepath.Join(os.TempDir(), "wireguard-loop", ifaceName+".sock")
}

// waitForSocket waits for the UAPI socket file to appear, polling until timeout.
func waitForSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("UAPI socket %s did not appear within %v", path, timeout)
}

func TestEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wireguard-loop-go does not support Windows")
	}

	loopBin := findLoopBinary(t)
	ifaceName := fmt.Sprintf("wgtest%d", os.Getpid())

	// === 1. Start wireguard-loop-go as a subprocess ===
	cmd := exec.Command(loopBin, "-f", ifaceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start wireguard-loop-go: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for UAPI socket to appear
	sockPath := uapiSocketPath(ifaceName)
	waitForSocket(t, sockPath, 5*time.Second)
	t.Logf("UAPI socket ready: %s", sockPath)

	// === 2. Generate keys for both sides ===

	// Our handler (side A)
	handler, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	defer handler.Close()

	// wireguard-loop-go (side B) — generate a key pair for it
	loopPrivKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate loop private key: %v", err)
	}
	loopPubKey := loopPrivKey.PublicKey()

	// Each side authorizes the other as a peer
	handler.AddPeer(loopPubKey)

	// === 3. Open a UDP socket for WireGuard traffic ===
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer udpConn.Close()

	ourAddr := udpConn.LocalAddr().(*net.UDPAddr)
	t.Logf("our UDP endpoint: %s", ourAddr)

	// === 4. Configure wireguard-loop-go via UAPI ===
	// Keys are hex-encoded for UAPI protocol
	ourPubKey := handler.PublicKey()
	config := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=0.0.0.0/0\nendpoint=%s\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(loopPrivKey[:]),
		hex.EncodeToString(ourPubKey[:]),
		ourAddr.String(),
	)
	configureViaUAPI(t, sockPath, config)
	t.Log("wireguard-loop-go configured")

	// === 5. Receive handshake initiation from wireguard-loop-go ===
	// persistent_keepalive_interval=1 causes it to initiate immediately
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, remoteAddr, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read handshake initiation: %v", err)
	}
	t.Logf("received %d bytes from %s (expecting handshake initiation)", n, remoteAddr)

	if n < 4 {
		t.Fatalf("packet too short: %d bytes", n)
	}
	msgType := binary_le_uint32(buf[0:4])
	if msgType != MessageInitiationType {
		t.Fatalf("expected message type %d (initiation), got %d", MessageInitiationType, msgType)
	}

	// === 6. Process handshake through our handler ===
	result, err := handler.ProcessPacket(buf[:n], remoteAddr.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("process handshake initiation: %v", err)
	}
	if result.Type != PacketHandshakeResponse {
		t.Fatalf("expected handshake response, got type %d", result.Type)
	}
	t.Logf("handshake initiation processed, sending %d-byte response", len(result.Response))

	// Send handshake response back
	if _, err := udpConn.WriteTo(result.Response, remoteAddr); err != nil {
		t.Fatalf("send handshake response: %v", err)
	}

	// Verify session is established
	if !handler.HasSession(loopPubKey) {
		t.Fatal("expected session to be established after handshake")
	}
	t.Log("session established")

	// === 7. Wait for a keepalive transport packet ===
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, remoteAddr, err = udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read keepalive: %v", err)
	}
	t.Logf("received %d bytes from %s (expecting keepalive/transport)", n, remoteAddr)

	result, err = handler.ProcessPacket(buf[:n], remoteAddr.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("process keepalive: %v", err)
	}
	if result.Type != PacketKeepalive {
		t.Fatalf("expected keepalive (type %d), got type %d", PacketKeepalive, result.Type)
	}
	t.Log("keepalive received — session confirmed live on both sides")

	// === 8. Send an encrypted IPv4 test packet ===
	testPayload := []byte("Hello, WireGuard loop!")
	testPacket := makeIPv4Packet(
		net.IPv4(10, 0, 0, 1).To4(),
		net.IPv4(10, 0, 0, 2).To4(),
		testPayload,
	)
	t.Logf("crafted %d-byte IPv4 test packet", len(testPacket))

	encrypted, err := handler.Encrypt(testPacket, loopPubKey)
	if err != nil {
		t.Fatalf("encrypt test packet: %v", err)
	}
	t.Logf("encrypted to %d bytes", len(encrypted))

	if _, err := udpConn.WriteTo(encrypted, remoteAddr); err != nil {
		t.Fatalf("send encrypted packet: %v", err)
	}

	// === 9. Receive the echoed packet back ===
	// wireguard-loop-go decrypts → loop echoes → re-encrypts → sends back
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read echo response: %v", err)
	}
	t.Logf("received %d-byte echo response", n)

	result, err = handler.ProcessPacket(buf[:n], remoteAddr.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("process echo response: %v", err)
	}
	if result.Type != PacketTransportData {
		t.Fatalf("expected transport data (type %d), got type %d", PacketTransportData, result.Type)
	}

	// Verify the echoed data matches what we sent.
	// wireguard-go pads transport plaintext to a multiple of 16 bytes,
	// so the echoed packet may be longer than what we sent.
	if len(result.Data) < len(testPacket) {
		t.Fatalf("echoed packet too short: got %d, want >= %d", len(result.Data), len(testPacket))
	}

	// Compare the original packet bytes
	for i := range testPacket {
		if result.Data[i] != testPacket[i] {
			t.Fatalf("echoed packet differs at byte %d: got 0x%02x, want 0x%02x", i, result.Data[i], testPacket[i])
		}
	}

	// Verify any padding bytes are zero
	for i := len(testPacket); i < len(result.Data); i++ {
		if result.Data[i] != 0 {
			t.Fatalf("padding byte %d is 0x%02x, expected 0x00", i, result.Data[i])
		}
	}

	t.Logf("echo verified: %d payload bytes match (%d bytes with padding)", len(testPacket), len(result.Data))
	t.Log("end-to-end test passed: handshake + keepalive + data echo all working")
}
