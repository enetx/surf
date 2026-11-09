package surf_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func nextSurfControlFrame(t *testing.T, peer *h3Peer) h3WireFrame {
	t.Helper()
	select {
	case frame := <-peer.controlFrames:
		return frame
	case err := <-peer.errors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("missing HTTP/3 control frame")
	}
	return h3WireFrame{}
}

func TestHTTP3WireFluentConfiguration(t *testing.T) {
	peer := newH3Peer(t)
	control := []surf.HTTP3GreaseFrame{{Type: 33, Payload: []byte("control")}}
	request := []surf.HTTP3GreaseFrame{{Type: 64, Payload: []byte("request")}}
	names := []string{"Cookie", ":method"}
	builder := surf.NewClient().Builder().ForceHTTP3()
	h3 := builder.HTTP3Settings().ControlGreaseFrames(control...).RequestGreaseFrames(request...).PriorityUpdates(true).QpackSplitCookies(true).QpackNeverIndex(names...)
	control[0].Payload[0] = '!'
	request[0].Payload[0] = '!'
	names[0] = "other"
	client := h3.Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	builder.HTTP3Settings().PriorityUpdates(false).QpackSplitCookies(false).QpackNeverIndex().ControlGreaseFrames().RequestGreaseFrames()
	for i := range 2 {
		resp := client.Get(g.String(peer.url+"/wire")).SetHeaders("priority", "u=1, i").SetHeaders("cookie", "one=1; two=2").Do()
		require.False(t, resp.IsErr(), "%v", resp.Err())
		require.Equal(t, g.String("ok"), resp.Ok().Body.String().Unwrap())
		var capture h3RequestCapture
		select {
		case capture = <-peer.requests:
		case <-time.After(time.Second):
			t.Fatal("missing request")
		}
		require.Len(t, capture.greaseFrames, 1)
		require.EqualValues(t, 64, capture.greaseFrames[0].kind)
		require.Equal(t, "request", string(capture.greaseFrames[0].payload))
		var cookies []string
		for _, field := range capture.headers {
			if field.Name == "cookie" {
				cookies = append(cookies, field.Value)
			}
		}
		require.Equal(t, []string{"one=1", "two=2"}, cookies)
		frame := nextSurfControlFrame(t, peer)
		if i == 0 {
			require.EqualValues(t, 33, frame.kind)
			require.Equal(t, "control", string(frame.payload))
			frame = nextSurfControlFrame(t, peer)
		}
		require.EqualValues(t, 0xf0700, frame.kind)
		id, n, err := quicvarint.Parse(frame.payload)
		require.NoError(t, err)
		require.EqualValues(t, capture.greaseFrames[0].streamID, id)
		require.Equal(t, "u=1, i", string(frame.payload[n:]))
	}
}

func TestHTTP3BrowserControlFrames(t *testing.T) {
	for _, firefox := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "firefox"}[firefox], func(t *testing.T) {
			peer := newH3Peer(t)
			im := surf.NewClient().Builder().Impersonate()
			var builder *surf.Builder
			if firefox {
				builder = im.Firefox()
			} else {
				builder = im.Chrome()
			}
			client := builder.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			peer.request(t, client)
			if firefox {
				frame := nextSurfControlFrame(t, peer)
				require.GreaterOrEqual(t, frame.kind, uint64(33))
				require.Zero(t, (frame.kind-33)%31)
				require.LessOrEqual(t, (frame.kind-33)/31, uint64(1<<57-1))
				require.LessOrEqual(t, len(frame.payload), 7)
				select {
				case frame := <-peer.controlFrames:
					t.Fatalf("unexpected Firefox frame %d", frame.kind)
				case <-time.After(30 * time.Millisecond):
				}
				return
			}
			frame := nextSurfControlFrame(t, peer)
			require.GreaterOrEqual(t, frame.kind, uint64(33))
			require.Zero(t, (frame.kind-33)%31)
			draw := (frame.kind - 33) / 31
			require.LessOrEqual(t, draw, uint64(1<<32-1))
			require.EqualValues(t, draw%4, len(frame.payload))
			frame = nextSurfControlFrame(t, peer)
			require.EqualValues(t, 0xf0700, frame.kind)
			id, n, err := quicvarint.Parse(frame.payload)
			require.NoError(t, err)
			require.Zero(t, id)
			require.Equal(t, "u=0, i", string(frame.payload[n:]))
		})
	}
}

func TestHTTP3WireFactoryErrors(t *testing.T) {
	peer := newH3Peer(t)
	client := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().RequestGreaseFramesFactory(func(*http.Request) ([]surf.HTTP3GreaseFrame, error) { return []surf.HTTP3GreaseFrame{{Type: 1}}, nil }).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(2 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	resp := client.Get(g.String(peer.url)).Do()
	require.True(t, resp.IsErr())
	require.ErrorContains(t, resp.Err(), "GREASE")
}

func TestHTTP3BrowserCookiePolicy(t *testing.T) {
	for _, firefox := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "firefox"}[firefox], func(t *testing.T) {
			peer := newH3Peer(t)
			im := surf.NewClient().Builder().Impersonate()
			var builder *surf.Builder
			if firefox {
				builder = im.Firefox()
			} else {
				builder = im.Chrome()
			}
			client := builder.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String(peer.url)).SetHeaders("cookie", "one=1; two=2").Do()
			require.False(t, response.IsErr(), "%v", response.Err())
			response.Ok().Body.Close()
			select {
			case capture := <-peer.requests:
				var cookies []string
				for _, f := range capture.headers {
					if f.Name == "cookie" {
						cookies = append(cookies, f.Value)
					}
				}
				want := []string{"one=1", "two=2"}
				if firefox {
					want = []string{"one=1; two=2"}
				}
				require.Equal(t, want, cookies)
			case <-time.After(time.Second):
				t.Fatal("missing HTTP/3 cookies")
			}
		})
	}
}

func TestHTTP3LocalFactoryNetworkErrorDoesNotFallback(t *testing.T) {
	peer := newH3Peer(t)
	var tcpDials atomic.Int32
	client := surf.NewClient().Builder().ForceHTTP3().
		With(func(c *surf.Client) error {
			c.GetTransport().(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
				tcpDials.Add(1)
				return nil, syscall.ECONNREFUSED
			}
			return nil
		}).
		HTTP3Settings().RequestGreaseFramesFactory(func(*http.Request) ([]surf.HTTP3GreaseFrame, error) {
		return nil, &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}
	}).
		Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(3 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String(peer.url)).Do()
	require.True(t, response.IsErr())
	var preparation *http3.RequestPreparationError
	require.ErrorAs(t, response.Err(), &preparation)
	require.ErrorIs(t, response.Err(), syscall.ENETUNREACH)
	require.Zero(t, tcpDials.Load())
}
