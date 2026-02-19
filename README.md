# wgnet

[![Tests](https://github.com/vpdotnet/wgnet/actions/workflows/test.yml/badge.svg)](https://github.com/vpdotnet/wgnet/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/vpdotnet/wgnet/badge.svg?branch=master)](https://coveralls.io/github/vpdotnet/wgnet?branch=master)

A Go library that abstracts the WireGuard protocol behind a simple interface: feed it UDP packets, get back decrypted network packets, and vice versa. All the cryptography, handshakes, session management, and replay protection are handled internally.

## Install

```
go get github.com/vpdotnet/wgnet
```

## Quick Start

```go
// Create a handler (generates a new identity if no private key is provided)
handler, _ := wgnet.NewHandler(wgnet.Config{})
defer handler.Close()

// Authorize peers by public key
handler.AddPeer(peerPublicKey)

// Start maintenance (cookie rotation, session cleanup)
go func() {
    for range time.Tick(10 * time.Second) {
        handler.Maintenance()
    }
}()
```

### Receiving: UDP in, network packets out

```go
// Read a UDP datagram from the wire
n, remoteAddr, _ := conn.ReadFromUDP(buf)

// Hand it to the handler
result, err := handler.ProcessPacket(buf[:n], remoteAddr)
if err != nil {
    log.Println(err)
    continue
}

switch result.Type {
case wgnet.PacketHandshakeResponse, wgnet.PacketCookieReply:
    // Protocol response — relay back over UDP
    conn.WriteToUDP(result.Response, remoteAddr)

case wgnet.PacketTransportData:
    // Decrypted network packet (e.g. IPv4/IPv6) ready for processing
    forward(result.Data, result.PeerKey)

case wgnet.PacketKeepalive:
    // Nothing to do
}
```

### Sending: network packets in, UDP out

```go
encrypted, _ := handler.Encrypt(ipPacket, peerPublicKey)
conn.WriteToUDP(encrypted, peerAddr)
```

## Multiple Identities on One Port

`MultiHandler` lets a single UDP socket serve multiple WireGuard server identities. Incoming packets are automatically routed to the correct handler based on MAC1 (handshakes) or receiver index (transport data).

```go
mh, _ := wgnet.NewMultiHandler(handler1, handler2)
defer mh.Close()

result, _ := mh.ProcessPacket(buf[:n], remoteAddr)
// result.Handler tells you which identity was targeted
fmt.Println("routed to", result.Handler.PublicKey())
```

Handlers can be added or removed at runtime:

```go
mh.AddHandler(handler3)
mh.RemoveHandler(handler2.PublicKey())
```

## Peer Management

```go
// Authorize with optional preshared key
handler.AddPeer(pubKey)
handler.AddPeerWithPSK(pubKey, psk)

// Auto-authorize unknown peers via callback
handler, _ := wgnet.NewHandler(wgnet.Config{
    OnUnknownPeer: func(pk wgnet.NoisePublicKey, addr *net.UDPAddr) bool {
        return isAllowed(pk)
    },
})

// Set peer expiry
handler.SetPeerExpiry(pubKey, time.Now().Add(24 * time.Hour))

// Remove peer (tears down session immediately)
handler.RemovePeer(pubKey)
```

## Key Generation

```go
privKey, _ := wgnet.GeneratePrivateKey()
pubKey := privKey.PublicKey()
```

## License

MIT - see [LICENSE](LICENSE) for details.
