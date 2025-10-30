<p align="center">
  <img src="https://user-images.githubusercontent.com/65846651/233453773-33f38b64-0adc-41b4-8e13-a49c89bf9db6.png">
</p>

<h1>Surf - Advanced HTTP Client for Go</h1>

[![Go Reference](https://pkg.go.dev/badge/github.com/enetx/surf.svg)](https://pkg.go.dev/github.com/enetx/surf)
[![Go Report Card](https://goreportcard.com/badge/github.com/enetx/surf)](https://goreportcard.com/report/github.com/enetx/surf)
[![Coverage Status](https://coveralls.io/repos/github/enetx/surf/badge.svg?branch=main&service=github)](https://coveralls.io/github/enetx/surf?branch=main)
[![Go](https://github.com/enetx/surf/actions/workflows/go.yml/badge.svg)](https://github.com/enetx/surf/actions/workflows/go.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/enetx/surf)

<p>Surf is a powerful, feature-rich HTTP client library for Go that makes working with HTTP requests intuitive and enjoyable. With advanced features like browser impersonation, JA3/JA4 fingerprinting, and comprehensive middleware support, Surf provides everything you need for modern web interactions.</p>

## ✨ Key Features

### 🎭 **Browser Impersonation**
- **Chrome & Firefox Support**: Accurately mimic Chrome v142 and Firefox v144 browser fingerprints
- **Platform Diversity**: Impersonate Windows, macOS, Linux, Android, and iOS devices
- **TLS Fingerprinting**: Full JA3/JA4 fingerprint customization for enhanced privacy
- **Automatic Headers**: Proper header ordering and browser-specific values
- **WebKit Form Boundaries**: Accurate multipart form boundary generation matching real browsers

### 🔒 **Advanced TLS & Security**
- **Custom JA3/JA4**: Configure precise TLS fingerprints with `HelloID` and `HelloSpec`
- **HTTP/3 Support**: Full HTTP/3 over QUIC with complete browser-specific QUIC fingerprinting
- **JA4QUIC Fingerprinting**: Complete QUIC transport parameter fingerprinting for Chrome and Firefox
- **HTTP/2 & HTTP/3**: Full HTTP/2 support with customizable settings (SETTINGS frame, window size, priority)
- **Ordered Headers**: Browser-accurate header ordering for perfect fingerprint evasion
- **Certificate Pinning**: Custom TLS certificate validation
- **DNS-over-TLS**: Enhanced privacy with DoT support
- **Proxy Support**: HTTP, HTTPS, and SOCKS5 proxy configurations with UDP support for HTTP/3

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

**Required Go version:** 1.24+

## 🔄 Standard Library Compatibility

Surf provides seamless integration with Go's standard `net/http` package, allowing you to use Surf's advanced features with any library that expects a standard `*http.Client`.

```go
// Create a Surf client with advanced features
surfClient := surf.NewClient().
    Builder().
    Impersonate().Chrome().
    Session().
    Build()

// Convert to standard net/http.Client
stdClient := surfClient.Std()

// Use with any third-party library
// Example: AWS SDK, Google APIs, OpenAI client, etc.
resp, err := stdClient.Get("https://api.example.com")
```

**Preserved Features When Using Std():**
- ✅ JA3/TLS fingerprinting
- ✅ HTTP/2 settings
- ✅ HTTP/3 & QUIC fingerprinting
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

    fmt.Println(resp.Ok().Body.String())
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
    Chrome().        // Latest Chrome v142
    Build()

resp := client.Get("https://example.com").Do()
```

### Firefox with Random OS

```go
client := surf.NewClient().
    Builder().
    Impersonate().
    RandomOS().      // Randomly selects Windows, macOS, Linux, Android, or iOS
    FireFox().       // Latest Firefox v144
    Build()
```

### Platform-Specific Impersonation

```go
// iOS Chrome
client := surf.NewClient().
    Builder().
    Impersonate().
    IOS().
    Chrome().
    Build()

// Android Chrome
client := surf.NewClient().
    Builder().
    Impersonate().
    Android().
    Chrome().
    Build()
```

## 🚀 HTTP/3 & Complete QUIC Fingerprinting

### Chrome HTTP/3 with Automatic Detection

```go
// Automatic HTTP/3 with Chrome fingerprinting
client := surf.NewClient().
    Builder().
    Impersonate().Chrome().
    HTTP3().        // Auto-detects Chrome and applies appropriate QUIC settings
    Build()

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
    Impersonate().FireFox().
    HTTP3().        // Auto-detects Firefox and applies Firefox QUIC settings
    Build()

resp := client.Get("https://cloudflare-quic.com/").Do()
```

### Manual HTTP/3 Configuration

```go
// Custom QUIC fingerprint with Chrome settings
client := surf.NewClient().
    Builder().
    HTTP3Settings().Chrome().Set().
    Build()

// Custom QUIC fingerprint with Firefox settings
client := surf.NewClient().
    Builder().
    HTTP3Settings().Firefox().Set().
    Build()

// Custom QUIC ID
client := surf.NewClient().
    Builder().
    HTTP3Settings().
    SetQUICID(uquic.QUICChrome_115).
    Set().
    Build()

// Custom QUIC Spec
spec, _ := uquic.QUICID2Spec(uquic.QUICFirefox_116)
client := surf.NewClient().
    Builder().
    HTTP3Settings().
    SetQUICSpec(spec).
    Set().
    Build()
```

### HTTP/3 with Complete Fingerprinting

```go
// Combine TLS fingerprinting with HTTP/3 QUIC fingerprinting
client := surf.NewClient().
    Builder().
    JA().Chrome142().               // TLS fingerprint (JA3/JA4)
    HTTP3Settings().Chrome().Set().  // Complete QUIC fingerprint (JA4QUIC)
    Build()

resp := client.Get("https://cloudflare-quic.com/").Do()
```

### HTTP/3 Compatibility & Fallbacks

HTTP/3 automatically handles compatibility issues:

```go
// With HTTP proxy - automatically falls back to HTTP/2
client := surf.NewClient().
    Builder().
    Proxy("http://proxy:8080").     // HTTP proxies incompatible with HTTP/3
    HTTP3Settings().Chrome().Set(). // Will use HTTP/2 instead
    Build()

// With SOCKS5 proxy - HTTP/3 works over UDP
client := surf.NewClient().
    Builder().
    Proxy("socks5://127.0.0.1:1080"). // SOCKS5 UDP proxy supports HTTP/3
    HTTP3Settings().Chrome().Set().   // Will use HTTP/3 over SOCKS5
    Build()

// With DNS settings - works seamlessly
client := surf.NewClient().
    Builder().
    DNS("8.8.8.8:53").             // Custom DNS works with HTTP/3
    HTTP3Settings().Chrome().Set().
    Build()

// With DNS-over-TLS - works seamlessly
client := surf.NewClient().
    Builder().
    DNSOverTLS().Google().          // DoT works with HTTP/3
    HTTP3Settings().Chrome().Set().
    Build()
```

**Key HTTP/3 Features:**
- ✅ **Complete QUIC Fingerprinting**: Full Chrome and Firefox QUIC transport parameter matching
- ✅ **Header Ordering**: Perfect browser-like header sequence preservation
- ✅ **SOCKS5 UDP Support**: HTTP/3 works seamlessly over SOCKS5 UDP proxies
- ✅ **Automatic Fallback**: Smart fallback to HTTP/2 when HTTP proxies are configured
- ✅ **DNS Integration**: Custom DNS and DNS-over-TLS support
- ✅ **JA4QUIC Support**: Advanced QUIC fingerprinting with Initial Packet + TLS ClientHello
- ✅ **Order Independence**: `HTTP3()` works regardless of call order

## 🔧 Advanced Configuration

### Custom JA3 Fingerprint

```go
// Use specific browser versions
client := surf.NewClient().
    Builder().
    JA().
    Chrome().     // Latest Chrome
    Build()


// Randomized fingerprints for evasion
client := surf.NewClient().
    Builder().
    JA().
    Randomized().    // Random TLS fingerprint
    Build()

// With custom HelloID
client := surf.NewClient().
    Builder().
    JA().
    SetHelloID(utls.HelloChrome_Auto).
    Build()

// With custom HelloSpec
client := surf.NewClient().
    Builder().
    JA().
    SetHelloSpec(customSpec).
    Build()
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
    Build()
```

### HTTP/3 Configuration

```go
// Automatic browser detection
client := surf.NewClient().
    Builder().
    Impersonate().Chrome().
    HTTP3().
    Build()

// Manual configuration
client := surf.NewClient().
    Builder().
    HTTP3Settings().Chrome().Set().
    Build()
```

### Proxy Configuration

```go
// Single proxy
client := surf.NewClient().
    Builder().
    Proxy("http://proxy.example.com:8080").
    Build()

// Rotating proxies
proxies := []string{
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "socks5://proxy3.example.com:1080",
}

client := surf.NewClient().
    Builder().
    Proxy(proxies).  // Randomly selects from list
    Build()
```

### SOCKS5 UDP Proxy Support
Surf supports HTTP/3 over SOCKS5 UDP proxies, combining the benefits of modern QUIC protocol with proxy functionality:

```go
// HTTP/3 over SOCKS5 UDP proxy
client := surf.NewClient().
    Builder().
    Proxy("socks5://127.0.0.1:1080").
    Impersonate().Chrome().
    HTTP3().  // Uses HTTP/3 over SOCKS5 UDP
    Build()

// SOCKS5 with custom DNS resolution
client := surf.NewClient().
    Builder().
    DNS("8.8.8.8:53").              // Custom DNS resolver
    Proxy("socks5://proxy:1080").   // SOCKS5 UDP proxy
    HTTP3().                        // HTTP/3 over SOCKS5
    Build()
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
    Build()
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
    Build()
```

### Client Middleware

```go
client := surf.NewClient().
    Builder().
    With(func(client *surf.Client) {
        // Modify client configuration
        client.GetClient().Timeout = 30 * time.Second
    }).
    Build()
```

## 📤 Request Types

### POST with JSON

```go
user := map[string]string{
    "name": "John Doe",
    "email": "john@example.com",
}

resp := surf.NewClient().
    Post("https://api.example.com/users", user).
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
    Post("https://example.com/login", formData).
    Do()

// Ordered form data (preserves field insertion order)
orderedForm := g.NewMapOrd[string, string]()
orderedForm.Set("username", "john")
orderedForm.Set("password", "secret")
orderedForm.Set("remember_me", "true")

resp := surf.NewClient().
    Post("https://example.com/login", orderedForm).
    Do()
```

### File Upload

```go
// Single file upload
resp := surf.NewClient().
    FileUpload(
        "https://api.example.com/upload",
        "file",                    // field name
        "/path/to/file.pdf",       // file path
    ).Do()

// With additional form fields
extraData := g.MapOrd[string, string]{
    "description": "Important document",
    "category": "reports",
}

resp := surf.NewClient().
    FileUpload(
        "https://api.example.com/upload",
        "file",
        "/path/to/file.pdf",
        extraData,
    ).Do()
```

### Multipart Form

```go
fields := g.NewMapOrd[g.String, g.String]()
fields.Set("field1", "value1")
fields.Set("field2", "value2")

resp := surf.NewClient().
    Multipart("https://api.example.com/form", fields).
    Do()
```

## 🔄 Session Management

### Persistent Sessions

```go
client := surf.NewClient().
    Builder().
    Session().        // Enable cookie jar
    Build()

// Login
client.Post("https://example.com/login", credentials).Do()

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
    case resp.Ok().StatusCode.IsRedirect():
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

    // As string
    content := body.String()

    // As bytes
    data := body.Bytes()

    // MD5 hash
    hash := body.MD5()

    // UTF-8 conversion
    utf8Content := body.UTF8()

    // Check content
    if body.Contains("success") {
        fmt.Println("Request succeeded!")
    }

    // Save to file
    err := body.Dump("response.html")
}
```

### Streaming Large Responses

```go
resp := surf.NewClient().Get("https://example.com/large-file").Do()
if resp.IsOk() {
    reader := resp.Ok().Body.Stream()

    scanner := bufio.NewScanner(reader)
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
        fmt.Printf("Event: %s, Data: %s\n", event.Name, event.Data)
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
        fmt.Printf("TLS Version: %s\n", tlsInfo.Version)
        fmt.Printf("Cipher Suite: %s\n", tlsInfo.CipherSuite)
        fmt.Printf("Server Name: %s\n", tlsInfo.ServerName)

        for _, cert := range tlsInfo.PeerCertificates {
            fmt.Printf("Certificate CN: %s\n", cert.Subject.CommonName)
        }
    }
}
```

## ⚡ Performance Optimization

### Connection Reuse with Singleton

```go
// Create a reusable client
client := surf.NewClient().
    Builder().
    Singleton().      // Enable connection pooling
    Impersonate().
    Chrome().
    Build()

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
    Build()

resp := client.Get("https://api.example.com/data").Do()
if resp.IsOk() {
    // First access reads from network
    data1 := resp.Ok().Body.Bytes()

    // Subsequent accesses use cache
    data2 := resp.Ok().Body.Bytes()  // No network I/O
}
```

### Retry Configuration

```go
client := surf.NewClient().
    Builder().
    Retry(3, 2*time.Second).           // Max 3 retries, 2 second wait
    RetryCodes(http.StatusTooManyRequests, http.StatusServiceUnavailable).
    Build()
```

## 🌐 Advanced Features

### H2C (HTTP/2 Cleartext)

```go
// Enable HTTP/2 without TLS
client := surf.NewClient().
    Builder().
    H2C().
    Build()

resp := client.Get("http://localhost:8080/h2c-endpoint").Do()
```

### Custom Headers Order

```go
// Control exact header order for fingerprinting evasion
headers := g.NewMapOrd[g.String, g.String]()
headers.Set("User-Agent", "Custom/1.0")
headers.Set("Accept", "*/*")
headers.Set("Accept-Language", "en-US")
headers.Set("Accept-Encoding", "gzip, deflate")

client := surf.NewClient().
    Builder().
    SetHeaders(headers).  // Headers will be sent in this exact order
    Build()
```

### Custom DNS Resolver

```go
client := surf.NewClient().
    Builder().
    Resolver("8.8.8.8:53").  // Use Google DNS
    Build()
```

### DNS-over-TLS

```go
client := surf.NewClient().
    Builder().
    DNSOverTLS("1.1.1.1:853").  // Cloudflare DoT
    Build()
```

### Unix Domain Sockets

```go
client := surf.NewClient().
    Builder().
    UnixSocket("/var/run/docker.sock").
    Build()

resp := client.Get("http://localhost/v1.41/containers/json").Do()
```

### Network Interface Binding

```go
client := surf.NewClient().
    Builder().
    InterfaceAddr("192.168.1.100").  // Bind to specific IP
    Build()
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
| `Get(url, params...)` | Creates a GET request |
| `Post(url, data)` | Creates a POST request |
| `Put(url, data)` | Creates a PUT request |
| `Patch(url, data)` | Creates a PATCH request |
| `Delete(url, data...)` | Creates a DELETE request |
| `Head(url)` | Creates a HEAD request |
| `FileUpload(url, field, path, data...)` | Creates a multipart file upload |
| `Multipart(url, fields)` | Creates a multipart form request |
| `Raw(raw, scheme)` | Creates a request from raw HTTP |

### Builder Methods

| Method | Description |
|--------|-------------|
| `Impersonate()` | Enable browser impersonation |
| `JA()` | Configure JA3/JA4 fingerprinting |
| `HTTP2Settings()` | Configure HTTP/2 parameters |
| `HTTP3Settings()` | Configure HTTP/3 & QUIC parameters |
| `HTTP3()` | Enable HTTP/3 with automatic browser detection |
| `H2C()` | Enable HTTP/2 cleartext |
| `Proxy(proxy)` | Set proxy configuration (string, []string for rotation) |
| `DNS(dns)` | Set custom DNS resolver |
| `DNSOverTLS()` | Configure DNS-over-TLS |
| `Session()` | Enable cookie jar for sessions |
| `Singleton()` | Enable connection pooling (reuse client) |
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
| `UnixDomainSocket(path)` | Use Unix socket |
| `InterfaceAddr(addr)` | Bind to network interface |
| `Boundary(fn)` | Custom multipart boundary generator |
| `Std()` | Convert to standard net/http.Client |

### Request Methods

| Method | Description |
|--------|-------------|
| `Do()` | Execute the request |
| `WithContext(ctx)` | Add context to request |
| `SetHeaders(headers...)` | Set request headers |
| `AddHeaders(headers...)` | Add request headers |
| `AddCookies(cookies...)` | Add cookies to request |

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

### Body Methods

| Method | Description |
|--------|-------------|
| `String()` | Get body as string |
| `Bytes()` | Get body as bytes |
| `JSON(v)` | Decode JSON into struct |
| `XML(v)` | Decode XML into struct |
| `MD5()` | Calculate MD5 hash |
| `UTF8()` | Convert to UTF-8 |
| `Stream()` | Get buffered reader |
| `SSE(fn)` | Process Server-Sent Events |
| `Dump(file)` | Save to file |
| `Contains(pattern)` | Check if contains pattern |
| `Limit(n)` | Limit body size |
| `Close()` | Close body reader |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [enetx/http](https://github.com/enetx/http) for enhanced HTTP functionality
- HTTP/3 support and complete QUIC fingerprinting powered by [uQUIC](https://github.com/enetx/uquic)
- TLS fingerprinting powered by [uTLS](https://github.com/enetx/utls)
- Generic utilities from [enetx/g](https://github.com/enetx/g)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/enetx/surf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/enetx/surf/discussions)
- **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/enetx/surf)

---

<p align="center">
  <b>Made with ❤️ by the Surf contributors</b>
</p>
