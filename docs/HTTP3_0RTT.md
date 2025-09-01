# HTTP/3 0-RTT Support in Surf

## Overview

Surf now supports 0-RTT (Zero Round-Trip Time) for HTTP/3 connections, allowing faster connection resumption to previously visited servers. This feature can significantly reduce latency for subsequent requests to the same server.

## What is 0-RTT?

0-RTT allows clients to send application data immediately when resuming a connection to a server they've previously connected to, without waiting for the TLS handshake to complete. This is achieved by reusing cryptographic parameters from a previous session.

## Benefits

- **Reduced Latency**: Eliminates one round-trip time for connection establishment
- **Faster Page Loads**: Particularly beneficial for APIs and resources requiring multiple requests
- **Improved User Experience**: Noticeable performance improvement for repeat visitors

## How to Enable 0-RTT

### Basic Configuration

```go
client := surf.NewClient().
    Builder().
    HTTP3Settings().
    Chrome().           // Use Chrome fingerprint
    Set().
    Session().          // Enable session caching for 0-RTT
    Build()

defer client.CloseIdleConnections()
```

### Configuration Options

#### Session()
Enables TLS session caching, which is required for 0-RTT to work. When enabled, the client will automatically attempt to use 0-RTT for subsequent connections to servers that support it.

```go
.Session()  // Enable unlimited session cache
```

This uses Go's built-in `tls.NewLRUClientSessionCache(0)` with unlimited capacity.

## Complete Example

```go
package main

import (
    "log"
    "time"
    
    "github.com/enetx/surf"
)

func main() {
    // Create HTTP/3 client with session caching (enables 0-RTT)
    client := surf.NewClient().
        Builder().
        HTTP3Settings().
        Chrome().
        Set().
        Session().
        Build()
    
    defer client.CloseIdleConnections()
    
    // First request - establishes connection and gets session ticket
    start := time.Now()
    resp := client.Get("https://cloudflare.com/").Do()
    if resp.IsErr() {
        log.Fatal(resp.Err())
    }
    firstDuration := time.Since(start)
    log.Printf("First request: %v", firstDuration)
    
    // Subsequent request - uses 0-RTT if available
    start = time.Now()
    resp = client.Get("https://cloudflare.com/api/").Do()
    if resp.IsErr() {
        log.Fatal(resp.Err())
    }
    secondDuration := time.Since(start)
    log.Printf("Second request: %v (%.1f%% faster)", 
        secondDuration, 
        (1-float64(secondDuration)/float64(firstDuration))*100)
}
```

## Important Considerations

### Security Implications

0-RTT has some security trade-offs:

1. **Replay Attacks**: 0-RTT data can potentially be replayed by an attacker
2. **No Forward Secrecy**: Initial 0-RTT data doesn't have perfect forward secrecy
3. **Idempotent Operations Only**: Should only be used for safe, idempotent operations (GET, HEAD)

### Server Support

Not all servers support 0-RTT. The feature requires:
- HTTP/3 support on the server
- 0-RTT enabled in server configuration
- Valid session tickets from previous connections

### Session Lifetime

Session tickets typically expire after:
- 7 days (common default)
- Server-configured timeout
- Server restart or configuration change

### Performance Notes

- **First connection**: Never uses 0-RTT (needs prior session)
- **Network latency**: Benefits most visible on high-latency connections (satellite, mobile, international)
- **Local connections**: May show minimal improvement due to already fast round-trips
- **Server processing**: Benefits may be masked by server response time
- **Real-world impact**: Most significant for mobile users and repeat visitors

#### Why you might not see dramatic improvements:

1. **Fast local networks**: 0-RTT saves ~1 round-trip (few milliseconds locally)
2. **Server response time**: Often dominates total request time
3. **Connection reuse**: HTTP/3 already reuses connections efficiently
4. **Server support**: Not all servers have 0-RTT enabled

#### When 0-RTT provides the most benefit:

- High-latency networks (satellite, mobile, international)
- API clients making frequent requests
- Real-time applications
- Mobile apps with intermittent connectivity

## Testing 0-RTT

You can verify 0-RTT is working by:

1. Comparing connection times for first vs subsequent requests
2. Using network debugging tools to observe the handshake
3. Checking server logs for 0-RTT indicators

## Browser Compatibility

When using browser fingerprints (Chrome/Firefox), the 0-RTT implementation maintains compatibility with the impersonated browser's behavior.

## Troubleshooting

If 0-RTT doesn't seem to work:

1. **Verify server support**: Not all servers support 0-RTT
2. **Check session cache**: Ensure session cache is enabled and has capacity
3. **Timing**: Sessions may expire or be invalidated by the server
4. **Network conditions**: Some network configurations may prevent 0-RTT

## Future Improvements

Planned enhancements for 0-RTT support:
- Alt-Svc header processing for automatic HTTP/3 discovery
- Connection metrics and monitoring
- Automatic fallback strategies
- Advanced session management options