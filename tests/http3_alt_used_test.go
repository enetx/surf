package surf_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestHTTP3AltUsedOnWire(t *testing.T) {
	for _, tc := range []struct {
		name      string
		method    string
		configure func(*surf.Builder) *surf.Builder
		explicit  *string
		want      bool
	}{
		{name: "firefox-get", method: "GET", want: true},
		{name: "firefox-post", method: "POST", want: true},
		{name: "explicit-authority", method: "GET", explicit: new("alternative.example:8443"), want: true},
		{name: "explicit-empty", method: "GET", explicit: new(""), want: true},
		{name: "disabled", method: "GET", configure: func(b *surf.Builder) *surf.Builder { return b.HTTP3Settings().AltUsed(false).Set() }},
		{name: "chrome-default", method: "GET", configure: func(b *surf.Builder) *surf.Builder { return b.Impersonate().Chrome() }},
		{name: "chrome-opt-in", method: "GET", want: true, configure: func(b *surf.Builder) *surf.Builder {
			return b.Impersonate().Chrome().HTTP3Settings().AltUsed(true).Set()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newH3Peer(t)
			builder := surf.NewClient().Builder().Impersonate().MacOS().Firefox()
			if tc.configure != nil {
				builder = tc.configure(builder)
			}
			client := builder.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			request := client.Get(g.String(peer.url + "/wire"))
			if tc.method == "POST" {
				request = client.Post(g.String(peer.url + "/wire"))
			}
			if tc.explicit != nil {
				request.SetHeaders("Alt-Used", *tc.explicit)
			}
			original := request.GetRequest()
			response := request.Do().Unwrap()
			require.Equal(t, "ok", response.Body.String().Unwrap().Std())
			require.Equal(t, 3, response.GetResponse().ProtoMajor)
			select {
			case capture := <-peer.requests:
				var values []string
				altIndex, encodingIndex := -1, -1
				for i, field := range capture.headers {
					if field.Name == "alt-used" {
						values = append(values, field.Value)
						altIndex = i
					}
					if field.Name == "accept-encoding" {
						encodingIndex = i
					}
				}
				if tc.want {
					want := strings.TrimPrefix(peer.url, "https://")
					if tc.explicit != nil {
						want = *tc.explicit
					}
					require.Equal(t, []string{want}, values)
					if strings.HasPrefix(tc.name, "firefox-") {
						require.Equal(t, encodingIndex+1, altIndex)
					}
				} else {
					require.Empty(t, values)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("peer did not record request")
			}
			if tc.explicit == nil {
				require.NotContains(t, original.Header, "Alt-Used", "RoundTrip mutated caller headers")
			}
		})
	}
}

func TestHTTP3AltUsedFollowsDestination(t *testing.T) {
	first, second := newH3Peer(t), newH3Peer(t)
	client := surf.NewClient().Builder().Impersonate().MacOS().Firefox().ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	for _, peer := range []*h3Peer{first, second, first} {
		capture := peer.request(t, client)
		var values []string
		for _, field := range capture.headers {
			if field.Name == "alt-used" {
				values = append(values, field.Value)
			}
		}
		require.Equal(t, []string{strings.TrimPrefix(peer.url, "https://")}, values)
	}
}

func TestHTTP3AltUsedDoesNotLeakToProxyFallback(t *testing.T) {
	headers := make(chan http.Header, 1)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case headers <- r.Header.Clone():
		default:
		}
		w.Write([]byte("ok"))
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		downstream, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer downstream.Close()
		if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = buffer.Flush(); err != nil {
			return
		}
		go func() { defer upstream.Close(); io.Copy(upstream, buffer) }()
		io.Copy(downstream, upstream)
	}))
	defer proxy.Close()
	client := surf.NewClient().Builder().Impersonate().MacOS().Firefox().ForceHTTP3().Proxy(g.String(proxy.URL)).TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String(origin.URL + "/wire")).Do().Unwrap()
	require.Equal(t, "ok", response.Body.String().Unwrap().Std())
	require.Equal(t, 2, response.GetResponse().ProtoMajor)
	select {
	case received := <-headers:
		require.Empty(t, received.Get("Alt-Used"))
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive fallback request")
	}
}
