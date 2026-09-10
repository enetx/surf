package surf_test

import (
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/enetx/surf/profiles/chrome"
	utls "github.com/refraction-networking/utls"
)

// helloRecorder is a bare TCP listener that reads the ClientHello of every incoming connection,
// records its extension IDs in wire order and drops the connection. It never completes a TLS
// handshake: the client side is expected to fail, the bytes on the wire are the subject.
type helloRecorder struct {
	ln     net.Listener
	mu     sync.Mutex
	hellos [][]uint16
}

func newHelloRecorder(t *testing.T) *helloRecorder {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	r := &helloRecorder{ln: ln}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := r.ln.Accept()
			if err != nil {
				return
			}

			go func() {
				// The append happens before the close, so a client that has observed EOF is
				// guaranteed to see the ClientHello already recorded.
				defer conn.Close()

				conn.SetReadDeadline(time.Now().Add(5 * time.Second))

				if exts, ok := readClientHelloExtensions(conn); ok {
					r.mu.Lock()
					r.hellos = append(r.hellos, exts)
					r.mu.Unlock()
				}
			}()
		}
	}()

	return r
}

func (r *helloRecorder) url() g.String { return g.String("https://" + r.ln.Addr().String() + "/") }

// collect drives n requests through a client configured by fn and returns every ClientHello
// seen, normalised down to what the shuffle actually governs: GREASE IDs collapse to a single
// placeholder (uTLS randomises them per connection) and padding is dropped (it is emitted only
// when the ClientHello has to be padded to a target length, so its presence varies with the
// GREASE values). Both are positionally invariant and never take part in a shuffle.
func (r *helloRecorder) collect(t *testing.T, n int, fn func(*surf.Builder) *surf.Builder) [][]uint16 {
	t.Helper()

	client := fn(surf.NewClient().Builder()).Timeout(5 * time.Second).Build().Unwrap()
	for range n {
		client.Get(r.url()).Do()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.hellos) < n {
		t.Fatalf("recorded %d ClientHellos, want at least %d", len(r.hellos), n)
	}

	out := make([][]uint16, 0, len(r.hellos))
	for _, hello := range r.hellos {
		ids := make([]uint16, 0, len(hello))
		for _, id := range hello {
			switch {
			case id == extensionPadding:
			case isGREASE(id):
				ids = append(ids, utls.GREASE_PLACEHOLDER)
			default:
				ids = append(ids, id)
			}
		}
		out = append(out, ids)
	}

	return out
}

// extensionPadding is the client_hello padding extension (RFC 7685).
const extensionPadding uint16 = 21

// isGREASE reports whether an extension ID is one of the 16 GREASE code points.
func isGREASE(id uint16) bool { return id&0x0f0f == 0x0a0a && byte(id>>8) == byte(id) }

// readClientHelloExtensions parses one TLS handshake record and returns the extension IDs of
// the ClientHello it carries, in wire order.
func readClientHelloExtensions(conn net.Conn) ([]uint16, bool) {
	var record [5]byte
	if _, err := io.ReadFull(conn, record[:]); err != nil || record[0] != 0x16 {
		return nil, false
	}

	body := make([]byte, binary.BigEndian.Uint16(record[3:5]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, false
	}

	// handshake type (1) + handshake length (3) + legacy_version (2) + random (32)
	if len(body) < 38 || body[0] != 0x01 {
		return nil, false
	}

	pos := 38

	take := func(n int) ([]byte, bool) {
		if n < 0 || pos+n > len(body) {
			return nil, false
		}

		v := body[pos : pos+n]
		pos += n

		return v, true
	}

	// legacy_session_id, cipher_suites, legacy_compression_methods
	for _, sizeLen := range []int{1, 2, 1} {
		size, ok := take(sizeLen)
		if !ok {
			return nil, false
		}

		n := int(size[0])
		if sizeLen == 2 {
			n = int(binary.BigEndian.Uint16(size))
		}

		if _, ok := take(n); !ok {
			return nil, false
		}
	}

	size, ok := take(2)
	if !ok {
		return nil, false
	}

	var (
		end  = pos + int(binary.BigEndian.Uint16(size))
		exts []uint16
	)

	for pos < end {
		head, ok := take(4)
		if !ok {
			return nil, false
		}

		exts = append(exts, binary.BigEndian.Uint16(head[:2]))

		if _, ok := take(int(binary.BigEndian.Uint16(head[2:]))); !ok {
			return nil, false
		}
	}

	return exts, true
}

// assertSameExtensionSet fails when the recorded ClientHellos do not all carry the same
// extensions — a shuffle is allowed to reorder them, never to add or drop any.
func assertSameExtensionSet(t *testing.T, hellos [][]uint16) {
	t.Helper()

	want := slices.Sorted(slices.Values(hellos[0]))
	for i, hello := range hellos[1:] {
		if got := slices.Sorted(slices.Values(hello)); !slices.Equal(got, want) {
			t.Fatalf("ClientHello %d carries a different extension set\n got: %v\nwant: %v", i+1, got, want)
		}
	}
}

// ordersVary reports whether at least two of the recorded ClientHellos differ in order.
func ordersVary(hellos [][]uint16) bool {
	for _, hello := range hellos[1:] {
		if !slices.Equal(hello, hellos[0]) {
			return true
		}
	}

	return false
}

func TestJAShuffleExtensionsVariesPerConnection(t *testing.T) {
	t.Parallel()

	r := newHelloRecorder(t)
	hellos := r.collect(t, 8, func(b *surf.Builder) *surf.Builder {
		return b.JA().ShuffleExtensions().SetHelloSpec(chrome.HelloChrome_152)
	})

	assertSameExtensionSet(t, hellos)

	if !ordersVary(hellos) {
		t.Errorf("extension order identical across %d connections, ShuffleExtensions had no effect", len(hellos))
	}
}

func TestJAWithoutShuffleKeepsExtensionOrder(t *testing.T) {
	t.Parallel()

	r := newHelloRecorder(t)
	hellos := r.collect(t, 8, func(b *surf.Builder) *surf.Builder {
		return b.JA().SetHelloSpec(chrome.HelloChrome_152)
	})

	assertSameExtensionSet(t, hellos)

	if ordersVary(hellos) {
		t.Errorf("extension order changed without ShuffleExtensions:\n%v", hellos)
	}
}

// TestJAShuffleExtensionsAppliesToHelloID guards the ClientHelloID branch of JA.getSpec: an
// explicit ShuffleExtensions must reach it too, instead of being silently dropped.
func TestJAShuffleExtensionsAppliesToHelloID(t *testing.T) {
	t.Parallel()

	r := newHelloRecorder(t)
	hellos := r.collect(t, 8, func(b *surf.Builder) *surf.Builder {
		return b.JA().ShuffleExtensions().SetHelloID(utls.HelloChrome_120)
	})

	assertSameExtensionSet(t, hellos)

	if !ordersVary(hellos) {
		t.Errorf("extension order identical across %d connections on the ClientHelloID path", len(hellos))
	}
}

// TestJAChrome152ShufflesExtensions covers the built-in profile: the shuffle must come from the
// per-connection path, not from a one-off shuffle baked into chrome.HelloChrome_152 at init.
func TestJAChrome152ShufflesExtensions(t *testing.T) {
	t.Parallel()

	before := make([]utls.TLSExtension, len(chrome.HelloChrome_152.Extensions))
	copy(before, chrome.HelloChrome_152.Extensions)

	r := newHelloRecorder(t)
	hellos := r.collect(t, 8, func(b *surf.Builder) *surf.Builder { return b.JA().Chrome152() })

	assertSameExtensionSet(t, hellos)

	if !ordersVary(hellos) {
		t.Errorf("Chrome152 sent an identical extension order across %d connections", len(hellos))
	}

	if !slices.Equal(before, chrome.HelloChrome_152.Extensions) {
		t.Error("chrome.HelloChrome_152 was mutated in place, the shuffle must run on a clone")
	}
}
