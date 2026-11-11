<p align="center">
  <img src="https://user-images.githubusercontent.com/65846651/233453773-33f38b64-0adc-41b4-8e13-a49c89bf9db6.png">
</p>

<h1>Surf - Advanced HTTP Client for Go</h1>

[![Go Reference](https://pkg.go.dev/badge/github.com/enetx/surf.svg)](https://pkg.go.dev/github.com/enetx/surf)
[![Coverage Status](https://coveralls.io/repos/github/enetx/surf/badge.svg?branch=main&service=github)](https://coveralls.io/github/enetx/surf?branch=main)
[![Go](https://github.com/enetx/surf/actions/workflows/go.yml/badge.svg)](https://github.com/enetx/surf/actions/workflows/go.yml)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)
[![Ask DeepWiki](https://img.shields.io/badge/Ask-DeepWiki-2f80ed)](https://deepwiki.com/enetx/surf)

<p>Surf is a powerful, feature-rich HTTP client library for Go that makes working with HTTP requests intuitive and enjoyable. With advanced features like browser impersonation, JA3/JA4 fingerprinting, and comprehensive middleware support, Surf provides everything you need for modern web interactions.</p>

## ✨ Key Features

### 🎭 **Browser Impersonation**
- **Chrome & Firefox Support**: Accurately mimic Chrome v157 (desktop/Android), Chrome v157 (iOS), and Firefox v160 (desktop) browser fingerprints
- **Platform Diversity**: Impersonate Windows, macOS, Linux, Android, and iOS devices
- **TLS Fingerprinting**: Full JA3/JA4 fingerprint customization for enhanced privacy
- **Automatic Headers**: Proper header ordering and browser-specific values
- **WebKit Form Boundaries**: Accurate multipart form boundary generation matching real browsers

### 🔒 **Advanced TLS & Security**
- **Custom JA3/JA4**: Configure precise TLS fingerprints with `HelloID` and `HelloSpec`
- **HTTP/3 Support**: HTTP/3 over QUIC with customizable HTTP/3 settings
- **HTTP/2 & HTTP/3**: Full HTTP/2 support with customizable settings (SETTINGS frame, window size, priority)
- **Ordered Headers**: Browser-accurate header ordering for perfect fingerprint evasion
- **Certificate Pinning**: Custom TLS certificate validation
- **DNS-over-TLS**: Enhanced privacy with DoT support
- **Proxy Support**: HTTP, HTTPS, SOCKS4 and SOCKS5 proxy configurations with UDP support for HTTP/3

### 🚀 **Performance & Reliability**
- **Connection Pooling**: Efficient connection reuse with singleton pattern
- **Automatic Retries**: Configurable retry logic with custom status codes
- **Response Caching**: Built-in body caching for repeated access
- **Streaming Support**: Efficient handling of large responses and SSE
- **Compression**: Automatic decompression of gzip, deflate, brotli, and zstd responses
- **Keep-Alive**: Persistent connections with configurable parameters

### 🛠️ **Developer Experience**
- **Standard Library Compatible**: Convert to `net/http.Client` for third-party library integration
- **Fluent API**: Chainable methods for elegant code
- **Middleware System**: Extensible request/response/client middleware with priority support
- **Type Safety**: Strong typing with generics support via [enetx/g](https://github.com/enetx/g)
- **Debug Mode**: Comprehensive request/response debugging
- **Error Handling**: Result type pattern for better error management
- **Context Support**: Full context.Context integration for cancellation and timeouts

## 📦 Installation

```bash
go get -u github.com/enetx/surf
```

**Required Go version:** 1.27+

## 🔄 Standard Library Compatibility

Surf provides seamless integration with Go's standard `net/http` package, allowing you to use Surf's advanced features with any library that expects a standard `*http.Client`.

```go
// Create a Surf client with advanced features
surfClient := surf.NewClient().
    Builder().
    Impersonate().Chrome().
    Session().
    Build().
    Unwrap()

// Convert to standard net/http.Client
stdClient := surfClient.Std()

// Use with any third-party library
// Example: AWS SDK, Google APIs, OpenAI client, etc.
resp, err := stdClient.Get("https://api.example.com")
```

**Preserved Features When Using Std():**
- ✅ JA3/TLS fingerprinting
- ✅ HTTP/2, HTTP/3 settings && fingerprinting
- ✅ Browser impersonation headers
- ✅ Ordered headers
- ✅ Cookies and sessions
- ✅ Proxy configuration
- ✅ Custom headers and User-Agent
- ✅ Timeout settings
- ✅ Redirect policies
- ✅ Request/Response middleware

**Limitations with Std():**
- ❌ Retry logic (implement at application level)
- ❌ Response body caching
- ❌ Remote address tracking
- ❌ Request timing information

## 🚀 Quick Start

### Basic GET Request

Requires Go 1.27 or newer. Surf uses the released `github.com/enetx/http` module
for HTTP/1, HTTP/2 and HTTP/3.

```go
package main

import (
    "fmt"
    "log"
    "github.com/enetx/surf"
)

func main() {
    resp := surf.NewClient().Get("https://api.github.com/users/github").Do()
    if resp.IsErr() {
        log.Fatal(resp.Err())
    }

    fmt.Println(resp.Ok().Body.String().Unwrap())
}
```

### JSON Response Handling

```go
type User struct {
    Name     string `json:"name"`
    Company  string `json:"company"`
    Location string `json:"location"`
}

resp := surf.NewClient().Get("https://api.github.com/users/github").Do()
if resp.IsOk() {
    var user User
    resp.Ok().Body.JSON(&user)
    fmt.Printf("User: %+v\n", user)
}
```

## 🎭 Browser Impersonation

### Chrome Impersonation

```go
client := surf.NewClient().
    Builder().
    Impersonate().
    Chrome().        // Chrome v157
    Build().
    Unwrap()

resp := client.Get("https://example.com").Do()
```

`Impersonate().Chrome()` selects the current Chrome 157 profile for desktop and Android.
Its TLS and HTTP/2/HTTP/3 defaults are checked against Google Chrome 157.0.8103.51.
`JA().Chrome()` and `JA().Chrome157()` select the current TLS template; older
version-specific Chrome helpers have been removed.

`Impersonate().IOS().Chrome()` selects the separate WebKit profile from the Chrome 157
iOS capture, including its User-Agent, TLS, HTTP/2 settings and header order. It sends no
Chromium Client Hints. Each platform keeps one current profile and its own golden reference.

`Session()` preserves cookies and enables TLS resumption where the profile supports it.
Chrome desktop and Android add PSK on a new TLS 1.3 connection with a cached ticket;
reusing an existing connection does not create another ClientHello. The verified iOS
profile keeps full handshakes even with `Session()`; its cookies still persist.

HTTP/3 uses the minimal enetx QUIC fork with separate browser ClientHello templates.
Independent browser fixtures cover supported QUIC/TLS parameters, SETTINGS and
header order. The [wire notes](tests/testdata/wire/README.md) describe differences,
including transport scheduling, pacing, recovery and platform coverage.

Firefox desktop uses the current 160 TLS template and headers. `JA().Firefox()` and
`JA().Firefox160()` select that TLS fingerprint; `JA().Firefox148()` retains the native
uTLS preset. Android and iOS keep their existing 148 placeholders until verified
mobile captures are available.

### Firefox with Random OS

```go
client := surf.NewClient().
    Builder().
    Impersonate().
    RandomOS().      // Randomly selects Windows, macOS, Linux, Android, or iOS
    Firefox().       // Firefox profile for the selected OS
    Build().
    Unwrap()
```

### Platform-Specific Impersonation

```go
// iOS Chrome
client := surf.NewClient().
    Builder().
    Impersonate().
    IOS().
    Chrome().
    Build().
    Unwrap()

// Android Chrome
client := surf.NewClient().
    Builder().
    Impersonate().
    Android().
    Chrome().
    Build().
    Unwrap()
```

## 🚀 HTTP/3 & QUIC Fingerprinting

### Chrome HTTP/3 with Automatic Detection

```go
// Automatic HTTP/3 with Chrome fingerprinting
client := surf.NewClient().
    Builder().
    Impersonate().Chrome().
    ForceHTTP3().    // Auto-detects Chrome and applies appropriate HTTP/3 settings
    Build().
    Unwrap()

resp := client.Get("https://cloudflare-quic.com/").Do()
if resp.IsOk() {
    fmt.Printf("Protocol: %s\n", resp.Ok().Proto) // HTTP/3.0
}
```

### Firefox HTTP/3

```go
// Firefox with HTTP/3 fingerprinting
client := surf.NewClient().
    Builder().
    Impersonate().Firefox().
    ForceHTTP3().    // Auto-detects Firefox and applies Firefox HTTP/3 settings
    Build().
    Unwrap()

resp := client.Get("https://cloudflare-quic.com/").Do()
```

### Manual HTTP/3 Configuration

```go
// Custom fingerprint settings
client := surf.NewClient().
    Builder().
    HTTP3Settings().Grease().Set().
    Build().
    Unwrap()

```

Chrome 157 transport defaults follow the selected protocol, including fallback:
HTTP/1.1 sends Connection and lowercase Client Hints without a default Priority.
HTTP/2 and HTTP/3 preserve their own ordered defaults. Custom values take precedence.
`HTTP3Settings().CoalesceRequestHeaders(true)` stages initial priority, HEADERS
and bodyless FIN together when stream credit permits. QPACK distinguishes an
omitted peer capacity from an explicit zero through
`QpackEncoderCapacityRequiresSetting` and `QpackEncoderZeroCapacity`.

`ForceHTTP3()` attempts QUIC directly and registers the transport itself. UDP
unavailability and TCP-only proxies retain HTTP/2/HTTP/1 fallback; a SOCKS5 proxy
with UDP support can carry HTTP/3. Proxy routes keep separate TCP pools while
retaining the selected TLS profile. [Chrome157 audit](tests/testdata/wire/chrome_157_audit.json).

### Request encoding and control frames

HTTP/2 header encoding and HTTP/3 control frames can be configured through the
same fluent builders as SETTINGS. Browser policy stays in Surf; the HTTP and
QUIC modules expose generic mechanisms. HPACK, Huffman coding and QPACK's static
table retain their official implementations; dynamic QPACK state is isolated in
the existing QUIC fork.

```go
client := surf.NewClient().Builder().Impersonate().Firefox().
    HTTP2Settings().
    HpackRepresentation("x-private", surf.HPACKNeverIndex).
    Set().
    HTTP3Settings().
    QpackNeverIndex("x-private").
    Set().Build().Unwrap()
defer client.Close()
```

`HpackPolicy`, `HpackIndexingLimit`, `HpackHuffman` and
`HpackNameReferencePolicy` control literal representations and new table entries.
`HPACKNameReferenceFirst` selects the first matching static name, as Chromium
does. `HPACKIncrementalIndexing` reuses exact entries and emits incremental
literals even when an entry is too large, emptying the table in that case.
These are selected by the Chrome desktop and Android profiles; native defaults
remain available through the same builder.
`MaxEncoderHeaderTableSize` independently bounds the request encoder's table;
`HeaderTableSize` advertises the response decoder's capacity. The browser profiles
accept peer encoder-table growth up to the native engine's `math.MaxInt32` limit.
`HpackDeduplicateTableSizeUpdates` controls redundant capacity notifications.
`HeaderPriority` selects HTTP/2 priority per request; `ChainStreamDependencies`
links it to eligible open streams. Trailers inherit the header encoding policy,
without receiving the request's HEADERS priority.

`ControlGreaseFrames` / `RequestGreaseFrames` accept reserved frames; their
`Factory` variants generate fresh values per connection or request.
`PriorityUpdates` controls initial HTTP/3 priority frames independently of
GREASE and local QUIC `StreamPriority`. `QpackSplitCookies` and `QpackNeverIndex`
control request fields. Browser presets select these independently:

| Behavior | Chrome 157 desktop / Android | Firefox 160 desktop |
| --- | --- | --- |
| HPACK varying `:path` | Literal without indexing | Literal without indexing, including static paths |
| HPACK Authorization | Normal indexing | Never indexed |
| HPACK Cookie | Split pairs, normal indexing | Split pairs; pairs shorter than 20 bytes never indexed |
| HPACK new entries | Incremental literals; an oversized entry empties the table | At most half the table; none when capacity is below 128 |
| HPACK literal name reference | First static match, then newest dynamic name | Exact match, otherwise last matching name |
| HPACK Huffman | When shorter | Always for literal strings |
| Repeated unchanged HPACK capacity | No new instruction | Table-size instruction queued |
| HTTP/3 Cookie | Separate field per pair | Preserve a single joined field |
| QPACK insertion | Eligible names and values | Only names absent from both tables |
| QPACK Huffman | Only when strictly shorter | Always for literal strings |
| QPACK Insert names | Static/dynamic name references when available | Literal names |
| QPACK Base | Required Insert Count | Insert count before the section; post-base references |
| QPACK draining | Oldest quarter; duplicate eligible draining entries | No draining reservation |
| QPACK insertion failure | Continue trying later fields | Stop new insertions for this section |
| Control GREASE type | `31*n+33`, 32-bit draw | `31*n+33`, 57-bit draw |
| Control GREASE payload | Length `n%4` | Independent draw, length 0–7 |
| Initial HTTP/3 priority update | Explicit nondefault Priority | Disabled; Neqo uses updates for changed priority |

Sources are pinned to [Chrome 157's Quiche revision](https://github.com/chromium/chromium/blob/157.0.8103.51/DEPS)
and [Firefox 160.0](https://github.com/mozilla-firefox/firefox/tree/FIREFOX_160_0_RELEASE).
The profile functions link directly to the corresponding browser source files.
iOS profiles keep their WebKit behavior; these desktop engine policies are not
applied to iOS. Browser resource-loading decisions remain outside this API.
The [QPACK audit](tests/testdata/wire/qpack/README.md) records exact field-section
and encoder-stream comparisons. These do not establish complete packet timing,
loss recovery or browser workload equivalence.

See the [HTTP/2 custom example](examples/http/http2_custom/http2_custom.go) and
[HTTP/3 custom example](examples/http/http3_custom/http3_custom.go) for overrides.

### QUIC ACK scheduling

QUIC receive ACK scheduling is configurable through `QUICSettings()`:
`AckPacketThreshold`, `AckDecimation(after, threshold)`, `AckDelayRTTDivisor`,
`MinAckDelay`, `AckReordering`, `AckMissingPacketLimit` and `AckECN`.
Chrome profiles select the 2-to-10 threshold transition by packet-number span;
Firefox retains two packets and a 20 ms deadline. `ResetAckPolicy` restores
native receive scheduling. These controls do not negotiate ACK_FREQUENCY.
See [browser source audit and actual ACK observations](tests/testdata/wire/ack/README.md)
and the [custom HTTP/3 example](examples/http/http3_custom/http3_custom.go).

### HTTP/3 Compatibility & Fallbacks

HTTP/3 automatically handles compatibility issues:

```go
// With HTTP proxy - automatically falls back to HTTP/2
client := surf.NewClient().
    Builder().
    Proxy("http://proxy:8080").    // HTTP proxies incompatible with HTTP/3
    ForceHTTP3().                  // Will use HTTP/2 instead
    Build().
    Unwrap()

// With SOCKS5 proxy - HTTP/3 works over UDP
client := surf.NewClient().
    Builder().
    Proxy("socks5://127.0.0.1:1080").    // SOCKS5 UDP proxy supports HTTP/3
    ForceHTTP3().                        // Will use HTTP/3 over SOCKS5
    Build().
    Unwrap()

// With DNS settings - works seamlessly
client := surf.NewClient().
    Builder().
    DNS("8.8.8.8:53").   // Custom DNS works with HTTP/3
    ForceHTTP3().
    Build().
    Unwrap()

// With DNS-over-TLS - works seamlessly
client := surf.NewClient().
    Builder().
    DNSOverTLS().Google().   // DoT works with HTTP/3
    ForceHTTP3()
    Build().
    Unwrap()
```

**Key HTTP/3 Features:**
- ✅ **QUIC Controls**: Browser profiles and externally configurable transport parameters
- ✅ **Header Ordering**: Explicit regular and pseudo-header order
- ✅ **SOCKS5 UDP Support**: HTTP/3 works seamlessly over SOCKS5 UDP proxies
- ✅ **Automatic Fallback**: HTTP/2 or HTTP/1.1 fallback retains the configured TCP TLS fingerprint and protocol-specific header defaults
- ✅ **DNS Integration**: Custom DNS and DNS-over-TLS support
- ✅ **TLS Templates**: Separate HTTP/3 ClientHello templates with Surf's minimal uTLS fork
- ✅ **Order Independence**: `ForceHTTP3()` works regardless of call order

### Native HTTP/3 configuration

`QUICSettings()` uses the same chain-and-`Set()` pattern as `HTTP2Settings()`
and `HTTP3Settings()`. Each method changes one option while preserving Surf's
other defaults or the selected browser profile. Reopening either settings chain
retains earlier values. `ForceHTTP3()` selects the QUIC transport.

```go
client := surf.NewClient().Builder().
    Impersonate().Chrome().
    ForceHTTP3().
    QUICSettings().
    InitialStreamReceiveWindow(6 << 20).
    InitialConnectionReceiveWindow(15 << 20).
    InitialPacketSize(1250).
    DisablePathMTUDiscovery(true).
    ConnectionIDLength(8).
    EnableDatagrams(true).
    Set().
    HTTP3Settings().
    StreamPriority(0, true).
    MaxResponseHeaderBytes(262144).
    Set().
    Build().Unwrap()
```

QUIC methods cover versions, handshake/idle timeouts, keep-alive, flow-control
windows, stream limits, packet size/PMTU, token stores, reliable resets and tracing.
`Versions` accepts constants such as `quic.Version1` from `github.com/enetx/quic-go`.
Zero values retain quic-go's field-specific meaning; `KeepAlivePeriod(0)` disables
keep-alive. `InitialStreamReceiveWindow` replaces per-direction window overrides.
Explicit `ConnectionIDLength(0)` uses empty source IDs and dedicated sockets;
leaving it unset retains the profile's value or the native four-byte default.

`HTTP3Settings()` configures ordered SETTINGS, QPACK, header limits and local
stream priority. `AdditionalSettings` merges settings, preserving existing positions.
`QUICSettings().EnableDatagrams` configures both transport and HTTP/3 support.

`QUICSettings().LegacyAckFrequency(time.Millisecond).Set()` opts into the legacy
ACK_FREQUENCY receiver and advertises its minimum delay. Firefox configures this
through the same builder; Chrome leaves it off. Zero disables the extension.
Peer requests can change local ACK tolerance, delay and ignore_order behavior;
local ACK settings apply until the first valid request. This is separate from
`MinAckDelay`, which is the local RTT-based timer floor.

`QUICSettings().PeerAckFrequencyPolicy(policy).Set()` independently configures
outgoing legacy requests, enabled only after the peer advertises its minimum and
the handshake completes. Firefox uses live congestion window, datagram size and
RTT to target four ACKs per RTT, with tolerance 2..256 and 25% delay hysteresis.
Chrome leaves the sender disabled. Pass `nil` to disable outgoing requests.
Callbacks must be concurrency safe, return promptly and provide valid targets
even when no update is requested; the engine manages sequencing, ACK/loss and PTO.
`InitialCongestionWindowPackets(n)` selects a starting window in accounting
segments (2..10000); zero keeps the native count. Firefox selects 10 path-MTU
segments with RFC 9438 CUBIC and classic byte-based slow start. Chromium selects
32 segments of 1460 bytes, byte-mode CUBIC, two emulated connections and original
HyStart. These are source defaults; browser experiments can override them.
`CongestionControl`, `SlowStart`, `CongestionControlSegmentSize` and
`CongestionControlConnections` expose the same fluent controls to users.
Pacing and recovery scheduling retain the engine's behavior. The
[custom HTTP/3 example](examples/http/http3_custom/http3_custom.go) demonstrates
both controls through the builder.

HTTP/3 can race connection preparation against a TCP backup:

```go
client := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().
    HTTP3Settings().ConnectionRacing(true).Set().Build().Unwrap()
defer client.Close()
```

Enablement is explicit; profiles select the delay policy. Firefox uses the
pending-transaction backup timer of 100ms. Chrome's policy uses this client's
observed QUIC success/failure and RTT; Android adds its default 100ms main-job
delay when applicable. These observations do not implement the browser's full
Alt-Svc, persistent network state, DNS HTTPS records or Happy Eyeballs scheduler.
`TCPFallbackDelay(d)` overrides the policy (zero starts both handshakes immediately).
`ConnectionRacingPolicy(func(ConnectionRacingInfo) time.Duration)` supplies a custom
nonnegative delay; callbacks must return promptly and be concurrency safe.

Only handshakes and connection-level setup race. The selected normal transport
then owns the request body, including non-replayable `StreamingBody` readers.
An application error does not trigger a cross-protocol resend in this mode.
Ordinary transport retries for explicit rejection or connection reuse still apply.
Requests to one origin share preparation; canceling one waiter preserves others.
A QUIC handshake that loses to TCP can finish into the shared pool for later use.
`Close` cancels preparation; `CloseIdleConnections` also stops selected background
attempts. TCP dials and idle connections retain native transport cleanup rules.

Connection racing requires keep-alives and cannot be combined with `EarlyData`.
HTTP CONNECT proxies use the ordinary TCP path; SOCKS5 can prepare both protocols.
Disabling connection racing retains sequential fallback. Browser policy history
is local to the client, with inactive history bounded to 256 origins.

`HTTP3Settings().Grease().Set()` generates a fresh reserved SETTINGS pair for each
new connection. Chrome profiles use two independent uint32 draws, matching the
browser's identifier/value ranges. `GreaseFactory(factory)` accepts a custom
`func() (id uint64, value uint64, err error)`; `GreaseFactory(nil)` disables it.
The callback must be concurrency safe and return promptly. Invalid identifiers,
duplicate configured identifiers and errors fail before initial control writes.
Repeated requests on one connection keep the SETTINGS already sent.

Stream priority controls the local QUIC sender. It does not add a `Priority`
header or send HTTP/3 PRIORITY_UPDATE frames. Per-request overrides are available
through `http3.WithStreamPriority(ctx, http3.StreamPriority{...})`.
The [wire test notes](tests/testdata/wire/README.md) describe verified parameters
and remaining gaps in browser HTTP/3 matching.

Handshake controls also use `QUICSettings()`: `StreamReceiveWindows(local, remote,
uni)`, `MaxUDPPayloadSize`, `MaxDatagramFrameSize`, `MaxAckDelay`,
`ActiveConnectionIDLimit`, `InitialDestinationConnectionIDLength`,
`InitialPacketNumber` and `DisableClientHelloScrambling`. `OmitMaxUDPPayloadSize(true)`
provisions the protocol default receive size. A later `MaxUDPPayloadSize(size)`
resumes advertising an explicit limit. `InitialPacketNumber(number)` replaces a
profile's packet-number factory with that fixed value.

Initial packet layout and handshake flights are independently configurable:

```go
builder.QUICSettings().
    InitialPaddingMode(surf.InitialPaddingDatagram).
    HandshakeAckBeforeData(true).
    SortConnectionIDFrames(true).
    Set()
```

The Firefox profile selects these controls. Datagram padding is a zero tail after
long-header packets; a final 1-RTT packet carries encrypted padding instead.
Separating ACK and Finished adds no artificial timer and preserves TLS verification.
`InitialPaddingPacket` and `HandshakeAckBeforeData(false)` restore native framing.

`TransportParameterOrder(ids...)`, `TransportParameter(id, encodedValue)` and
`DisableTransportParameterGrease(bool)` configure parameter encoding without a
layout struct. Input slices are copied. These setters amend each fresh layout
produced by a browser factory, preserving its other values and randomization.
Disabling GREASE also removes reserved parameters generated by the browser
factory; enabling it selects the native QUIC generator.
`TransportParametersFactory` and `InitialPacketNumberFactory` allow custom
per-attempt generation. Factories may run concurrently. The low-level
`HTTP3Settings().QUICConfig` and `ClientHandshake` entry points remain available
for existing callers; no configuration structs are required by the fluent API.

`ClientHelloSpec(*utls.ClientHelloSpec)` supplies a private template snapshot;
`ClientHelloFactory(func() (utls.ClientHelloSpec, error))` produces a fresh template
per attempt. These accept explicit QUIC templates with ALPN and transport-parameter
extensions. TCP `JA()` templates are independent and are not silently reused.
Certificate verification and the supplied TLS session cache are retained. Invalid
templates return errors. [Wire notes](tests/testdata/wire/README.md) document the
remaining adapter limits and the migration status.

Surf uses the published `github.com/enetx/http` and `github.com/enetx/quic-go`
modules without local replacements. HTTP/3 is imported from
`github.com/enetx/quic-go/http3`; no uTLS dependency fork is required.
Sibling checkouts can be combined in a parent Go workspace during development:
`go work init ./http ./quic-go ./surf`. This keeps local paths out of release module files.

Nonzero `QpackMaxTableCapacity` enables a bounded receive-side dynamic QPACK table;
`QpackBlockedStreams` limits waiting request streams. Feedback, cancellation and
header-size limits are enforced. `QpackDynamicTable(true)` separately enables
dynamic request headers and trailers, capped by peer SETTINGS and the local
`QpackEncoderTableCapacity` budget. Chrome and Firefox desktop profiles enable it.

QPACK stream behavior uses the same HTTP/3 settings chain:

```go
builder.HTTP3Settings().
    QpackDynamicTable(true).
    QpackHuffman(surf.QPACKHuffmanAuto).
    QpackIndexing(surf.QPACKIndexAll).
    QpackDrainingFraction(.25).
    QpackPostBaseReferences(false).
    QpackLiteralInsertNames(false).
    QpackStopOnInsertionFailure(false).
    QpackMaxTrackedSections(4096).
    QpackStreamOrder(surf.QPACKDecoderStream, surf.QPACKEncoderStream).
    QpackEagerStreamTypes(false).
    QpackEncoderTableCapacity(65536).
    QpackEncoderCapacityTiming(surf.QPACKCapacityBeforeHeaders).
    Set()
```

`QpackStreamOrder` reserves IDs after the control stream while credit permits;
`QpackEagerStreamTypes` chooses startup type bytes or type bytes with the first
instruction. Capacity announcements use the smaller of the peer's limit and
`QpackEncoderTableCapacity`. They can be queued after peer SETTINGS or when
encoding the next outgoing HEADERS block. `QpackEncoderZeroCapacity(true)` also
emits the zero-capacity instruction, initializing a lazy encoder stream. Without
peer SETTINGS, requests remain static and do not wait. Independent QUIC streams
retain their native delivery ordering.

`QpackIndexingPolicy` optionally filters new insertions. `QpackNeverIndex`
prevents insertion and emits literals with N=1. Unacknowledged entries and entries
used by outstanding sections cannot be evicted. Section ACKs are processed in
FIFO order on each stream; cancellation releases that stream's sections without
advancing the acknowledged insert count. At the tracking budget or when the
bounded encoder queue is full, new sections use static encoding without waiting.
The default tracking budget is 4096 sections; zero restores that default.

Chrome desktop/Android reserve decoder then encoder streams, use lazy type bytes
and defer capacity announcements to HEADERS. Firefox desktop reserves encoder
then decoder streams, writes types eagerly and queues capacity after SETTINGS.
Each profile's behavior can be overridden through `HTTP3Settings()`; the QUIC
fork exposes only generic controls. See the [wire notes](tests/testdata/wire/README.md)
for source references and the limits of the browser comparison.

HTTP/3 request bodies have separate controls for reads and DATA framing:

```go
builder.HTTP3Settings().
    RequestBodyBufferSize(32 << 10).
    MaxDataFrameSize(16 << 10).
    Set()
```

`RequestBodyBufferSizePolicy(func(contentLength int64) int)` optionally selects
reads per request; unknown lengths are -1, and zero uses the native 8 KiB buffer.
`RequestBodyBufferSize` clears a previous policy. Both size options accept 0 through
16 MiB; `MaxDataFrameSize(0)` keeps one DATA frame per write. These options do not
set QUIC packet boundaries. Chrome desktop/Android select a buffer between
14,520 and 371,712 bytes using the body length. Firefox desktop uses the shipped
32,768-byte network segment preference. Firefox's first large DATA boundary can
still differ because Necko includes serialized request headers in that segment.

Use `request.HTTP3PriorityUpdates(func(*surf.HTTP3PriorityUpdater))` to retain a
handle for an open request. Its `Update(urgency, incremental)` method sends an
RFC 9218 control frame, suppresses repeats, validates urgency 0–7, and rejects
completed/canceled requests. `(3, false)` restores the default. The callback runs
after request HEADERS and must return promptly; each retry gets a fresh handle.
This does not change `StreamPriority`, which schedules local uploads.
`CompactPriorityUpdates(true)` selects Firefox's comma formatting; Chrome uses
comma-space. No resource loading policy is added.

`HTTP3Settings().EarlyData(true).Set()` opts bodyless GET/HEAD into 0-RTT with
standard TLS or browser ClientHello templates (including ECH) and a configured
`tls.ClientSessionCache`. Enable it only for
requests whose replay is acceptable. POST and requests with bodies wait for the
handshake. Rejection and HTTP 425 permit one 1-RTT retry. It is disabled by default;
use `ForceHTTP3()` when the selected profile normally enables discovery/racing.
Connection racing and address racing still require a full handshake.

```go
client := surf.NewClient().Builder().ForceHTTP3().
    TLSConfig(&tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(32)}).
    HTTP3Settings().EarlyData(true).Set().Build().Unwrap()
defer client.Close()
```

The [HTTP/3 behavior report](tests/testdata/wire/http3_behavior/README.md) records
browser captures, source references and remaining differences.

Chrome desktop/Android and Firefox desktop supply separate QUIC TLS factories;
iOS and Firefox mobile retain their previous defaults pending browser captures.
Firefox advertises compatible v1/v2 switching (RFC 9368/9369) and legacy
ACK_FREQUENCY. Its profile starts with v1 and lists v2 before v1 in authenticated
version information. `QUICSettings().CompatibleVersionNegotiation(true)` enables
the same client mechanism for custom configurations; `Versions` selects allowed
versions and the first flight. Native clients keep it disabled. Version validation,
Retry, key changes and version-scoped session/token caches are handled by the engine.
All browser values and randomization policy live in Surf; the QUIC fork has no
built-in browser presets or uTLS dependency.

Browser QUIC profiles use the same layout in `profiles/chrome/quic/` and
`profiles/firefox/quic/`: `config.go` implements `ConfigureQUIC` as a chain of
the same setters exposed by `QUICSettings()`, including handshake, TLS and CID
options. Profiles do not construct native QUIC configuration structs or share
mutable configuration objects. Each application starts with fresh builder state.
`KeepAlivePeriod(0)` is explicit to retain the browser profiles' disabled keep-alive.
`client_hello.go` builds a fresh TLS template, `transport_parameters.go`
owns per-attempt parameter layout and randomization, and `qpack.go` selects
stream initialization and capacity timing. Platform variants select
these profiles; HTTP/3 SETTINGS remain in their platform's `http3.go`.

The profile chains serve as manual configuration examples. Their public
`NewClientHelloSpec`, `NewTransportParameters` and Firefox's
`NewInitialPacketNumber` factories can be reused in application builder chains.
`profiles.Variant.ConfigureQUIC` uses the fluent `profiles.QUICConfig` contract;
Surf's adapter forwards it to the public setters and the dispatcher calls `Set()`.

The [browser example](examples/http/http3/http3.go) selects its OS and browser
explicitly in code. To compare with the supplied macOS Firefox capture, select
`profile.MacOS()`. Firefox desktop automatically adds `alt-used` on HTTP/3
attempts using the current destination authority:

```sh
go run ./examples/http/http3
```

The [custom HTTP/3 example](examples/http/http3_custom/http3_custom.go) demonstrates
builder overrides for QUIC windows, handshake parameters, TLS factory, CID length,
QPACK, datagrams, local header limits and stream priority. `-profile chrome` or
`-profile firefox` starts from fresh browser defaults; `-profile custom` sets
individual transport options through `QUICSettings()`. Custom values change the resulting fingerprint.

Chrome desktop/Android and Firefox desktop also enable automatic HTTP/3 discovery.
Use `SecureTLS()` so Alt-Svc advertisements can be authenticated. A new origin
uses TCP until a valid Alt-Svc or usable HTTPS DNS binding is available;
connection preparation then races without reading or replaying the request body.
`ForceHTTP1()` / `ForceHTTP2()` take precedence, while `ForceHTTP3()` retains its
direct QUIC attempt. `HTTP3Settings().Discovery(false).Set()` disables discovery.
The [discovery example](examples/http/http3_discovery/http3_discovery.go) demonstrates
this flow with an ordinary verified client.

Alternatives and failure history are bounded per client and origin. Alt-Svc
expiry, `Age`, `clear`, alternative host/port, original SNI and certificate
verification are retained. HTTPS DNS uses the configured DNS/DoT dial hook and
system resolver addresses on systems exposing `resolv.conf`; it never substitutes
a public resolver. `HTTPSRecordsLookup` integrates platform or application DNS
resolvers elsewhere. Bindings support priority, alias chains, ALPN, port, IP
hints, mandatory keys and ECH. DNS bindings also route TCP-only services without
changing Host/SNI; `no-default-alpn` can exclude the TCP backup. ECH configuration is retained on both QUIC and
TCP preparation, using standard TLS configuration and Surf's uTLS adapter. Rejected ECH is not retried without
ECH. Proxies bypass local HTTPS discovery. Application-owned transports/TLS
dialers and disabled TCP keep-alives retain their existing connection policy.

Chrome 157 and Firefox 160 provide real-ECH inner ClientHello policies from
their browser profile packages. The minimal `enetx/utls` fork preserves their
cipher order and complete shared extension payloads, including fields unknown
to Go. Custom templates can supply a policy through `JA().ECHClientHelloInner`
or `QUICSettings().ECHClientHelloInner` before the terminal builder method.
Real ECH supports TLS 1.3 session resumption on TCP and QUIC. The engine binds
the full private ClientHello and keeps real session identities out of the public
hello. Chrome omits the outer PSK; Firefox randomizes its identity, age and binder.
Opt-in `HTTP3Settings().EarlyData(true).Set()` also works with browser templates
and ECH, for bodyless GET/HEAD only. It requires a TLS session cache; POST and
requests with bodies wait for the full handshake.
The [ECH verification report](tests/testdata/wire/ech/README.md) distinguishes
native Chrome and independently decrypted Firefox TCP/QUIC captures, source
checks and local integration tests.
The [ECH example](examples/tls/ech/ech.go) prints the negotiated protocol and
`ConnectionState.ECHAccepted`; run it with `go run ./examples/tls/ech`.
It uses `www.cloudflare-quic.com`, which advertises both h3 and ECH at the time
of verification. `www.cloudflare.com` currently advertises h3 without ECH.
Forced HTTP/1, HTTP/2 and HTTP/3 retain enabled HTTPS DNS discovery for TLS
metadata. Built-in A/AAAA and HTTPS queries start together; Surf's own dialers
reuse those address results. Application-owned dialers retain resolution and
routing control. Chrome's optional HTTPS timer starts after address
queries finish (20% of their duration, bounded to 5–50 ms), matching its default
opportunistic ECH mode. Firefox waits for the HTTPS result or resolver/request
deadline. `HTTPSRecordsWait(nil)` removes the supplemental deadline, including
when an application requires HTTPS metadata. With Chrome's default opportunistic
policy, a late HTTPS answer can therefore leave ECH unused even on a capable
endpoint. Waiting longer cannot supply ECH when DNS advertises no config.
Explicit lookup callbacks own their timing. Address results remain scoped to
the lookup flight, since Go's resolver does not expose their TTL.
Authenticated ECH rejection can reconnect once with nonempty retry configs.
Certificate failures, a second rejection or missing configs fail without a
plaintext retry; DNS caches and the caller's TLS config remain unchanged.
HTTPS queries use the same custom `.DNS("address:53")` or `.DNSOverTLS()`
resolver as A/AAAA queries, regardless of its position relative to the profile
selector. An explicitly supplied `HTTPSRecordsLookup` owns HTTPS queries instead.

QUIC profiles now include send scheduling as fluent configuration. Chromium
uses scheduled pacing with PRR and a 2000 × 1460-byte window ceiling. Firefox
uses a two-packet leaky bucket, classic recovery and persistent-congestion
detection, without the engine's fixed congestion-window ceiling. Firefox has
separate Initial, Handshake and Application Data wire counters, with no artificial
random or PTO gaps; Chromium keeps a shared counter. `QUICSettings()` exposes `Pacing`, `PacingGains`,
`PacingBurstPackets`, `PacingGranularity`, `PacingLumpyBurst`,
`ProportionalRateReduction`, `RecoveryBurstPackets`,
`PersistentCongestionThreshold`, `MaxCongestionWindowPackets` and
`SeparatePacketNumberSpaces` and `PacketNumberSkipping`. Optional `AddressFallbackDelay` enables staggered
QUIC address attempts; this custom override is not enabled indiscriminately in
browser profiles. Native packet-history and integer safety limits still apply.

Chrome also enables `CachedInitialRTT(0x3127, 10*time.Millisecond, time.Second)`
and `InitialPTOMultiplier(3)`. A cold connection omits the RTT hint; replacing
the connection on the same client advertises its measured per-origin SRTT.
Proxy paths are excluded. The wire value stays measured while the local initial
estimate is clamped. `InitialRTT` supplies an explicit local-only estimate.
See the [two-connection example](examples/http/http3_rtt/http3_rtt.go) and
[pinned source checks](tests/testdata/wire/ech/resumption/RTT.md).

These controls reproduce the verified mechanisms and preset source values.
Browser DNS integration, persisted network experiments, OS scheduling and NIC
packet timing remain outside an exact browser identity claim.

`HTTP3Settings().AltUsed(false).Set()` disables the Firefox desktop profile's
automatic `alt-used` header; `AltUsed(true)` enables it for a custom profile.
For direct HTTP/3 the value follows the request URL. Discovery uses the actual
connected alternative authority; port 443 is omitted and other ports are preserved.
An explicit `Alt-Used` header takes precedence. Automatic values are added to a
private HTTP/3 attempt, so HTTP/1/2 fallback does not inherit them.

## 🔧 Advanced Configuration

### Custom JA3 Fingerprint

```go
// Use specific browser versions
client := surf.NewClient().
    Builder().
    JA().
    Chrome().     // Latest Chrome
    Build().
    Unwrap()


// Randomized fingerprints for evasion
client := surf.NewClient().
    Builder().
    JA().
    Randomized().    // Random TLS fingerprint
    Build().
    Unwrap()

// With custom HelloID
client := surf.NewClient().
    Builder().
    JA().
    SetHelloID(utls.HelloChrome_Auto).
    Build().
    Unwrap()

// With custom HelloSpec
client := surf.NewClient().
    Builder().
    JA().
    SetHelloSpec(customSpec).
    Build().
    Unwrap()
```

### HTTP/2 Configuration

```go
client := surf.NewClient().
    Builder().
    HTTP2Settings().
    HeaderTableSize(65536).
    EnablePush(0).
    InitialWindowSize(6291456).
    MaxHeaderListSize(262144).
    ConnectionFlow(15663105).
    Set().
    Build().
    Unwrap()
```

### HTTP/3 Configuration

```go
client := surf.NewClient().
    Builder().
	HTTP3Settings().
	QpackMaxTableCapacity(65536).
	MaxFieldSectionSize(262144).
	QpackBlockedStreams(100).
	H3Datagram(1).
	Grease().
	Set().
    Build().
    Unwrap()
```

### Proxy Configuration

```go
// Single proxy
client := surf.NewClient().
    Builder().
    Proxy("http://proxy.example.com:8080").
    Build().
    Unwrap()
```

### SOCKS5 UDP Proxy Support
Surf supports HTTP/3 over SOCKS5 UDP proxies, combining the benefits of modern QUIC protocol with proxy functionality:

```go
// HTTP/3 over SOCKS5 UDP proxy
client := surf.NewClient().
    Builder().
    Proxy("socks5://127.0.0.1:1080").
    Impersonate().Chrome().
    ForceHTTP3().  // Uses HTTP/3 over SOCKS5 UDP
    Build().
    Unwrap()

// SOCKS5 with custom DNS resolution
client := surf.NewClient().
    Builder().
    DNS("8.8.8.8:53").              // Custom DNS resolver
    Proxy("socks5://proxy:1080").   // SOCKS5 UDP proxy
    ForceHTTP3().                   // HTTP/3 over SOCKS5
    Build().
    Unwrap()
```

## 🔌 Middleware System

### Request Middleware

```go
client := surf.NewClient().
    Builder().
    With(func(req *surf.Request) error {
        req.AddHeaders("X-Custom-Header", "value")
        fmt.Printf("Request to: %s\n", req.GetRequest().URL)
        return nil
    }).
    Build().
    Unwrap()
```

### Response Middleware

```go
client := surf.NewClient().
    Builder().
    With(func(resp *surf.Response) error {
        fmt.Printf("Response status: %d\n", resp.StatusCode)
        fmt.Printf("Response time: %v\n", resp.Time)
        return nil
    }).
    Build().
    Unwrap()
```

### Client Middleware

```go
client := surf.NewClient().
    Builder().
    With(func(client *surf.Client) error {
        // Modify client configuration
        client.GetClient().Timeout = 30 * time.Second
        return nil
    }).
    Build().
    Unwrap()
```

## 📤 Request Types

### POST with JSON

```go
user := map[string]string{
    "name": "John Doe",
    "email": "john@example.com",
}

resp := surf.NewClient().
    Post("https://api.example.com/users").
    Body(user).
    Do()
```

### Form Data

```go
// Standard form data (field order not guaranteed)
formData := map[string]string{
    "username": "john",
    "password": "secret",
}

resp := surf.NewClient().
    Post("https://example.com/login").
    Body(formData).
    Do()

// Ordered form data (preserves field insertion order)
orderedForm := g.NewMapOrd[string, string]()
orderedForm.Insert("username", "john")
orderedForm.Insert("password", "secret")
orderedForm.Insert("remember_me", "true")

resp := surf.NewClient().
    Post("https://example.com/login").
    Body(orderedForm).
    Do()
```

### File Upload

```go
// Single file upload
mp := surf.NewMultipart().
    File("file", g.NewFile("/path/to/file.pdf"))

resp := surf.NewClient().
    Post("https://api.example.com/upload").
    Multipart(mp).
    Do()

// With additional form fields
mp := surf.NewMultipart().
    Field("description", "Important document").
    Field("category", "reports").
    File("file", g.NewFile("/path/to/file.pdf"))

resp := surf.NewClient().
    Post("https://api.example.com/upload").
    Multipart(mp).
    Do()
```

### Multipart Form

```go
// Simple multipart form with fields only
mp := surf.NewMultipart().
    Field("field1", "value1").
    Field("field2", "value2")

resp := surf.NewClient().
    Post("https://api.example.com/form").
    Multipart(mp).
    Do()

// Advanced multipart with files from different sources
mp := surf.NewMultipart().
    Field("description", "Multiple files").
    File("document", g.NewFile("/path/to/doc.pdf")).               // Physical file
    FileBytes("data", "data.json", g.Bytes(`{"key": "value"}`)).   // Bytes with custom filename
    FileString("text", "note.txt", "Hello, World!").               // String content
    FileReader("stream", "upload.bin", someReader).                // io.Reader
    ContentType("application/pdf")                                 // Custom Content-Type for last file

resp := surf.NewClient().
    Post("https://api.example.com/upload").
    Multipart(mp).
    Do()
```

## 🔄 Session Management

### Persistent Sessions

```go
client := surf.NewClient().
    Builder().
    Session().        // Enable cookie jar
    Build().
    Unwrap()

// Login
client.Post("https://example.com/login").Body(credentials).Do()

// Subsequent requests will include session cookies
resp := client.Get("https://example.com/dashboard").Do()
```

### Manual Cookie Management

```go
// Set cookies
cookies := []*http.Cookie{
    {Name: "session", Value: "abc123"},
    {Name: "preference", Value: "dark_mode"},
}

resp := surf.NewClient().
    Get("https://example.com").
    AddCookies(cookies...).
    Do()

// Get cookies from response
if resp.IsOk() {
    for _, cookie := range resp.Ok().Cookies {
        fmt.Printf("Cookie: %s = %s\n", cookie.Name, cookie.Value)
    }
}
```

## 📊 Response Handling

### Status Code Checking

```go
resp := surf.NewClient().Get("https://api.example.com/data").Do()

if resp.IsOk() {
    switch {
    case resp.Ok().StatusCode.IsSuccess():
        fmt.Println("Success!")
    case resp.Ok().StatusCode.IsRedirection():
        fmt.Println("Redirected to:", resp.Ok().Location())
    case resp.Ok().StatusCode.IsClientError():
        fmt.Println("Client error:", resp.Ok().StatusCode)
    case resp.Ok().StatusCode.IsServerError():
        fmt.Println("Server error:", resp.Ok().StatusCode)
    }
}
```

### Body Processing

```go
resp := surf.NewClient().Get("https://example.com/data").Do()
if resp.IsOk() {
    body := resp.Ok().Body

    // As string (returns g.Result[g.String])
    if content := body.String(); content.IsOk() {
        fmt.Println(content.Ok())
    }

    // As bytes (returns g.Result[g.Bytes])
    if data := body.Bytes(); data.IsOk() {
        fmt.Println(len(data.Ok()))
    }

    // UTF-8 conversion (returns g.Result[g.String])
    if utf8Content := body.UTF8(); utf8Content.IsOk() {
        fmt.Println(utf8Content.Ok())
    }

    // Check content
    if body.Contains("success") {
        fmt.Println("Request succeeded!")
    }

    // Save to file
    err := body.Dump("response.html")
}
```

### Streaming Request Bodies

Use `StreamingBody(reader)` to send a body without buffering it until EOF.
Pass an optional known length; omitted or -1 means unknown, while zero means empty.
Surf owns the reader and closes it. A blocking reader must provide a Close method
that unblocks Read. A direct stream is sent once; status retries are suppressed
and 307/308 redirects are returned without replaying the body.

Use a factory when retries, redirects or HTTP/3 fallback must reopen the source:

```go
response := client.Post("https://example.com/upload").
    StreamingBodyFactory(func() (io.ReadCloser, error) {
        return os.Open("upload.bin")
    }).Do()
```

The factory runs when sending, returns a fresh reader per attempt and owns no
shared cursor. See the [streaming upload example](examples/post/post_stream/post_stream.go).

### Streaming Large Responses

```go
resp := surf.NewClient().Get("https://example.com/large-file").Do()
if resp.IsOk() {
    stream := resp.Ok().Body.Stream()
    defer stream.Close()

    scanner := bufio.NewScanner(stream)
    for scanner.Scan() {
        fmt.Println(scanner.Text())
    }
}
```

### Server-Sent Events (SSE)

```go
resp := surf.NewClient().Get("https://example.com/events").Do()
if resp.IsOk() {
    resp.Ok().Body.SSE(func(event *sse.Event) bool {
        fmt.Printf("Event: %s, Data: %s\n", event.Event, event.Data)
        return true  // Continue reading (false to stop)
    })
}
```

## 🔍 Debugging

### Request/Response Debugging

```go
resp := surf.NewClient().
    Get("https://api.example.com").
    Do()

if resp.IsOk() {
    resp.Ok().Debug().
        Request().      // Show request details
        Response(true). // Show response with body
        Print()
}
```

### TLS Information

```go
resp := surf.NewClient().Get("https://example.com").Do()
if resp.IsOk() {
    if tlsInfo := resp.Ok().TLSGrabber(); tlsInfo != nil {
        fmt.Printf("TLS Version: %s\n", tlsInfo.TLSVersion)
        fmt.Printf("Server Name: %s\n", tlsInfo.ExtensionServerName)
        fmt.Printf("Fingerprint: %s\n", tlsInfo.FingerprintSHA256)
        fmt.Printf("Common Name: %v\n", tlsInfo.CommonName)
        fmt.Printf("Organization: %v\n", tlsInfo.Organization)
    }
}
```

## ⚡ Performance Optimization

### Connection Reuse

```go
// Create a reusable client
client := surf.NewClient().
    Builder().
    Impersonate().
    Chrome().
    Build().
    Unwrap()

// Reuse for multiple requests
for i := 0; i < 100; i++ {
    resp := client.Get("https://api.example.com/data").Do()
    // Process response
}

// Clean up when done
defer client.CloseIdleConnections()
```

### Response Caching

```go
client := surf.NewClient().
    Builder().
    CacheBody().      // Enable body caching
    Build().
    Unwrap()

resp := client.Get("https://api.example.com/data").Do()
if resp.IsOk() {
    // First access reads from network
    data1 := resp.Ok().Body.Bytes().Unwrap()

    // Subsequent accesses use cache
    data2 := resp.Ok().Body.Bytes().Unwrap()  // No network I/O
}
```

### Retry Configuration

```go
client := surf.NewClient().
    Builder().
    Retry(3, 2*time.Second).           // Max 3 retries, 2 second wait
    Build().
    Unwrap()
```

## 🌐 Advanced Features

### H2C (HTTP/2 Cleartext)

```go
// Enable HTTP/2 without TLS
client := surf.NewClient().
    Builder().
    H2C().
    Build().
    Unwrap()

resp := client.Get("http://localhost:8080/h2c-endpoint").Do()
```

### Custom Headers Order

```go
// Control exact header order for fingerprinting evasion
headers := g.NewMapOrd[g.String, g.String]()
headers.Insert("User-Agent", "Custom/1.0")
headers.Insert("Accept", "*/*")
headers.Insert("Accept-Language", "en-US")
headers.Insert("Accept-Encoding", "gzip, deflate")

client := surf.NewClient().
    Builder().
    SetHeaders(headers).  // Headers will be sent in this exact order
    Build().
    Unwrap()
```

### Custom DNS Resolver

```go
client := surf.NewClient().
    Builder().
    DNS("8.8.8.8:53").  // Use Google DNS
    Build().
    Unwrap()
```

### DNS-over-TLS

```go
client := surf.NewClient().
    Builder().
    DNSOverTLS().Cloudflare().  // Cloudflare DoT
    Build().
    Unwrap()
```

### Unix Domain Sockets

```go
client := surf.NewClient().
    Builder().
    UnixSocket("/var/run/docker.sock").
    Build().
    Unwrap()

resp := client.Get("http://localhost/v1.41/containers/json").Do()
```

### Network Interface Binding

```go
client := surf.NewClient().
    Builder().
    InterfaceAddr("192.168.1.100").  // Bind to specific IP
    Build().
    Unwrap()
```

### Raw HTTP Requests

```go
rawRequest := `GET /api/data HTTP/1.1
Host: example.com
User-Agent: Custom/1.0
Accept: application/json

`

resp := surf.NewClient().
    Raw(g.String(rawRequest), "https").
    Do()
```

## 📚 API Reference

### Client Methods

| Method | Description |
|--------|-------------|
| `NewClient()` | Creates a new HTTP client with defaults |
| `Get(url)` | Creates a GET request |
| `Post(url)` | Creates a POST request |
| `Put(url)` | Creates a PUT request |
| `Patch(url)` | Creates a PATCH request |
| `Delete(url)` | Creates a DELETE request |
| `Head(url)` | Creates a HEAD request |
| `Options(url)` | Creates an OPTIONS request |
| `Connect(url)` | Creates a CONNECT request |
| `Trace(url)` | Creates a TRACE request |
| `Raw(raw, scheme)` | Creates a request from raw HTTP |
| `Builder()` | Returns a new Builder for client configuration |
| `Std()` | Convert to standard `*net/http.Client` |
| `CloseIdleConnections()` | Closes idle connections while keeping client usable |
| `Close()` | Completely shuts down the client and releases all resources |

### Builder Methods

| Method | Description |
|--------|-------------|
| `Impersonate()` | Enable browser impersonation |
| `JA()` | Configure JA3/JA4 fingerprinting |
| `HTTP2Settings()` | Configure HTTP/2 parameters |
| `HTTP3Settings()` | Configure HTTP/3 parameters |
| `H2C()` | Enable HTTP/2 cleartext |
| `Proxy(proxy)` | Set proxy configuration |
| `DNS(dns)` | Set custom DNS resolver |
| `DNSOverTLS()` | Configure DNS-over-TLS |
| `Session()` | Enable cookie jar for sessions |
| `Timeout(duration)` | Set request timeout |
| `MaxRedirects(n)` | Set maximum redirects |
| `NotFollowRedirects()` | Disable redirect following |
| `FollowOnlyHostRedirects()` | Only follow same-host redirects |
| `ForwardHeadersOnRedirect()` | Forward headers on redirects |
| `RedirectPolicy(fn)` | Custom redirect policy function |
| `Retry(max, wait, codes...)` | Configure retry logic |
| `CacheBody()` | Enable response body caching |
| `With(middleware, priority...)` | Add middleware |
| `BasicAuth(auth)` | Set basic authentication |
| `BearerAuth(token)` | Set bearer token authentication |
| `UserAgent(ua)` | Set custom user agent |
| `SetHeaders(headers...)` | Set request headers |
| `AddHeaders(headers...)` | Add request headers |
| `AddCookies(cookies...)` | Add cookies |
| `WithContext(ctx)` | Add context |
| `ContentType(type)` | Set content type |
| `GetRemoteAddress()` | Track remote address |
| `DisableKeepAlive()` | Disable keep-alive |
| `DisableCompression()` | Disable compression |
| `ForceHTTP1()` | Force HTTP/1.1 |
| `ForceHTTP2()` | Force HTTP/2 |
| `ForceHTTP3()` | Force HTTP/3 |
| `UnixSocket(path)` | Use Unix socket |
| `InterfaceAddr(addr)` | Bind to network interface |
| `Boundary(fn)` | Custom multipart boundary generator |

### Request Methods

| Method | Description |
|--------|-------------|
| `Do()` | Execute the request |
| `WithContext(ctx)` | Add context to request |
| `Body(data)` | Set request body (JSON, form data, bytes, string, io.Reader) |
| `StreamingBody(reader, length...)` | Send a reader without buffering; optional length |
| `StreamingBodyFactory(factory, length...)` | Open a fresh streaming reader for each attempt |
| `SetHeaders(headers...)` | Set request headers |
| `AddHeaders(headers...)` | Add request headers |
| `AddCookies(cookies...)` | Add cookies to request |
| `Multipart(mp)` | Set multipart form data for request |
| `GetRequest()` | Returns underlying `*http.Request` |

### Multipart Methods

| Method | Description |
|--------|-------------|
| `NewMultipart()` | Creates a new Multipart builder |
| `Field(name, value)` | Adds a form field |
| `File(fieldName, file)` | Adds a file from `*g.File` |
| `FileReader(fieldName, fileName, reader)` | Adds a file from `io.Reader` |
| `FileString(fieldName, fileName, content)` | Adds a file from string content |
| `FileBytes(fieldName, fileName, data)` | Adds a file from byte slice |
| `ContentType(ct)` | Sets custom Content-Type for the last added file |
| `FileName(name)` | Overrides filename for the last added file |
| `Retry()` | Buffers multipart body for retry support |

### Response Properties

| Property | Type | Description |
|----------|------|-------------|
| `StatusCode` | `StatusCode` | HTTP status code |
| `Headers` | `Headers` | Response headers |
| `Cookies` | `Cookies` | Response cookies |
| `Body` | `*Body` | Response body |
| `URL` | `*url.URL` | Final URL after redirects |
| `Time` | `time.Duration` | Request duration |
| `ContentLength` | `int64` | Content length |
| `Proto` | `string` | HTTP protocol version |
| `Attempts` | `int` | Number of retry attempts |

### Response Methods

| Method | Description |
|--------|-------------|
| `Debug()` | Returns debug info for request/response inspection |
| `Location()` | Returns the Location header (redirect URL) |
| `TLSGrabber()` | Returns TLS connection information |
| `Referer()` | Returns HTTP Referer header from original request |
| `GetResponse()` | Returns underlying `*http.Response` |
| `GetCookies(url)` | Returns cookies for a specific URL |
| `SetCookies(url, cookies)` | Stores cookies in client's cookie jar |
| `RemoteAddress()` | Returns remote server address |

### Body Methods

| Method | Description |
|--------|-------------|
| `String()` | Get body as string (returns `g.Result[g.String]`) |
| `Bytes()` | Get body as bytes (returns `g.Result[g.Bytes]`) |
| `JSON(v)` | Decode JSON into struct |
| `XML(v)` | Decode XML into struct |
| `UTF8()` | Convert to UTF-8 (returns `g.Result[g.String]`) |
| `Stream()` | Get StreamReader for streaming (with Close support) |
| `SSE(fn)` | Process Server-Sent Events |
| `Dump(file)` | Save to file |
| `Contains(pattern)` | Check if contains pattern |
| `Limit(n)` | Limit body size |
| `WithContext(ctx)` | Set context for cancellation of read operations |
| `Close()` | Close body reader |

## 🤝 Contributing

The root `surf` package owns the public client, builders, settings, callbacks and
adapters. Keep their names, signatures and import paths stable when moving code.
`GetTLSConfig()` and `GetDialer()` retain their shared configuration pointers.

| Location | Responsibility |
| --- | --- |
| `http2_settings.go` | HTTP/2 settings, HPACK and receive-window policy |
| `http3_settings.go`, `http3_qpack.go` | Public HTTP/3 types and fluent configuration |
| `quic_settings.go` | Public QUIC types and fluent configuration |
| `internal/http3` | HTTP/3 transport, DNS/discovery, ECH, protocol fallback and private tests |
| `internal/quic` | UDP ownership, QUIC dialing, SOCKS relay, address racing and private tests |
| `internal/connrace` | Shared connection preparation, cancellation and policy history, with private tests |
| `internal/quictls`, `internal/tlsstate`, `internal/specclone` | TLS integration, state conversion and template cloning |
| `internal/drainbody`, `internal/retryafter` | Body cleanup and Retry-After parsing |
| `profiles/`, `header/`, `pkg/` | Existing public profiles, header constants and supporting packages |
| `tests/` | Public API and wire behavior; internal tests stay with their implementation |

Public record types remain defined in `surf`; custom HTTPS lookups cross the
internal boundary through a checked struct conversion. Builders retain their
existing methods and return types. Browser policies remain in `profiles/`;
library refactoring preserves their wire fixtures and the coverage package list
in CI.

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ❤️ Support / Sponsorship

If you enjoy **Surf** and want to help keep development going, you can support the project with crypto donations:

| USDT | TON | SOL | BTC | ETH |
|--------------|-----|-----|-----|-----|
| <img src="https://github.com/user-attachments/assets/72ccb81c-f958-416b-86f6-349c759cdb93" width="100" /> | <img src="https://github.com/user-attachments/assets/49431b49-3e43-49a6-8083-2f5cb39d4f4e" width="100" /> | <img src="https://github.com/user-attachments/assets/d92ba4e9-408b-411e-bc08-473725a880f8" width="100" /> | <img src="https://github.com/user-attachments/assets/67a1ac0e-de90-4341-a13c-614eb213f5da" width="100" /> | <img src="https://github.com/user-attachments/assets/2e1b6c2b-f4b8-47ca-9785-f0512198ae49" width="100" /> |

Thank you for your support!

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [enetx/http](https://github.com/enetx/http) for enhanced HTTP functionality
- HTTP/3 support and configurable QUIC fingerprinting based on [QUIC-GO](https://github.com/quic-go/quic-go)
- TLS fingerprinting powered by the [minimal uTLS fork](https://github.com/enetx/utls), based on [official uTLS](https://github.com/refraction-networking/utls)
- Generic utilities from [enetx/g](https://github.com/enetx/g)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/enetx/surf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/enetx/surf/discussions)
- **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/enetx/surf)


<p align="center">
  <b>Made with ❤️ by the Surf contributors</b>
</p>
