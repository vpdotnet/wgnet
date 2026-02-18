# wgnet

A Go library implementing the WireGuard protocol for point-to-point connections.

Unlike the standard WireGuard implementation which is designed for multipoint networks, wgnet focuses on simple client/server endpoint connections. It handles the full Noise IKpsk2 handshake, transport encryption/decryption, replay protection, and session management.

## Install

```
go get github.com/vpdotnet/wgnet
```

## Usage

### Server

```go
handler, err := wgnet.NewHandler(wgnet.Config{
    // Optionally provide a static private key; omit to auto-generate.
    // PrivateKey: myKey,

    // Called when an unknown peer attempts to connect.
    OnUnknownPeer: func(pubKey wgnet.NoisePublicKey, addr *net.UDPAddr) bool {
        // Return true to accept, false to reject.
        return false
    },
})
if err != nil {
    log.Fatal(err)
}
defer handler.Close()

// Authorize a peer by its public key.
handler.AddPeer(peerPublicKey)

// Process incoming UDP packets.
result, err := handler.ProcessPacket(data, remoteAddr)
if err != nil {
    log.Println("error:", err)
    return
}

switch result.Type {
case wgnet.PacketHandshakeResponse, wgnet.PacketCookieReply:
    // Send result.Response back to remoteAddr.
    conn.WriteToUDP(result.Response, remoteAddr)

case wgnet.PacketTransportData:
    // result.Data contains the decrypted payload.
    handlePayload(result.Data, result.PeerKey)

case wgnet.PacketKeepalive:
    // Keepalive received, nothing to do.
}

// Encrypt data to send to a peer.
packet, err := handler.Encrypt(payload, peerPublicKey)
if err != nil {
    log.Println("encrypt:", err)
    return
}
conn.WriteToUDP(packet, peerAddr)
```

### Key Generation

```go
privKey, err := wgnet.GeneratePrivateKey()
if err != nil {
    log.Fatal(err)
}
pubKey := privKey.PublicKey()
```

### Preshared Keys

```go
handler.AddPeerWithPSK(peerPublicKey, presharedKey)
```

### Maintenance

Call `Maintenance()` periodically to rotate cookie secrets and clean up expired sessions:

```go
go func() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for range ticker.C {
        handler.Maintenance()
    }
}()
```

## License

MIT - see [LICENSE](LICENSE) for details.
