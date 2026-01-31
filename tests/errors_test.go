package surf_test

import (
	"crypto/tls"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http2"
	"github.com/enetx/surf"
)

func TestErrWebSocketUpgrade(t *testing.T) {
	t.Parallel()

	err := &surf.ErrWebSocketUpgrade{Msg: "client"}
	expected := "client received an unexpected response, switching protocols to WebSocket"

	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
}

func TestErrUserAgentType(t *testing.T) {
	t.Parallel()

	err := &surf.ErrUserAgentType{Msg: "invalid-type"}
	expected := "unsupported user agent type: invalid-type"

	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
}

func TestErr101ResponseCode(t *testing.T) {
	t.Parallel()

	err := &surf.Err101ResponseCode{Msg: "client"}
	expected := "client received a 101 response status code"

	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
}

func TestErrorTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			"ErrWebSocketUpgrade",
			&surf.ErrWebSocketUpgrade{Msg: "client"},
			"client received an unexpected response, switching protocols to WebSocket",
		},
		{
			"ErrUserAgentType",
			&surf.ErrUserAgentType{Msg: "invalid"},
			"unsupported user agent type: invalid",
		},
		{
			"Err101ResponseCode",
			&surf.Err101ResponseCode{Msg: "client"},
			"client received a 101 response status code",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.want {
				t.Errorf("expected %q, got %q", tc.want, tc.err.Error())
			}
		})
	}
}

func TestErrorTypesEmpty(t *testing.T) {
	t.Parallel()

	// Test with empty messages
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			"ErrWebSocketUpgrade empty",
			&surf.ErrWebSocketUpgrade{Msg: ""},
			" received an unexpected response, switching protocols to WebSocket",
		},
		{
			"ErrUserAgentType empty",
			&surf.ErrUserAgentType{Msg: ""},
			"unsupported user agent type: ",
		},
		{
			"Err101ResponseCode empty",
			&surf.Err101ResponseCode{Msg: ""},
			" received a 101 response status code",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.want {
				t.Errorf("expected %q, got %q", tc.want, tc.err.Error())
			}
		})
	}
}

func TestRoundTripperHTTP2FallbackErrorPreservesHTTP2Error(t *testing.T) {
	t.Parallel()

	// HTTP/1.1 handler: delay sending any headers so the fallback attempt hits
	// ResponseHeaderTimeout and fails with a timeout error.
	handler := func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should not be reached"))
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	ts.EnableHTTP2 = true
	ts.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			defer conn.Close()

			// Minimal HTTP/2 server that sends a stream reset with INTERNAL_ERROR.
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(conn, preface); err != nil {
				return
			}

			fr := http2.NewFramer(conn, conn)
			_ = fr.WriteSettings()

			for {
				f, err := fr.ReadFrame()
				if err != nil {
					return
				}

				switch f := f.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						_ = fr.WriteSettingsAck()
					}
				case *http2.HeadersFrame:
					_ = fr.WriteRSTStream(f.Header().StreamID, http2.ErrCodeInternal)
					return
				}
			}
		},
	}
	ts.StartTLS()
	defer ts.Close()

	result := surf.NewClient().Builder().
		With(func(c *surf.Client) error {
			c.GetTransport().(*http.Transport).ResponseHeaderTimeout = 50 * time.Millisecond
			return nil
		}).
		JA().Chrome144().
		Timeout(2 * time.Second).
		Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsOk() {
		t.Fatalf("expected error, got status %d", resp.Ok().StatusCode)
	}

	var fb *surf.ErrHTTP2Fallback
	if !resp.ErrAs(&fb) {
		t.Fatalf("expected ErrHTTP2Fallback, got %T: %v", resp.Err(), resp.Err())
	}

	if fb.HTTP2 == nil || fb.HTTP1 == nil {
		t.Fatalf("expected both HTTP2 and HTTP1 errors to be set: %+v", fb)
	}

	var se http2.StreamError
	if !resp.ErrAs(&se) {
		t.Fatalf("expected to find http2.StreamError via Unwrap, got: %v", resp.Err())
	}

	if se.Code != http2.ErrCodeInternal {
		t.Fatalf("expected HTTP/2 INTERNAL_ERROR, got %v", se.Code)
	}

	if !strings.Contains(resp.Err().Error(), "stream error") {
		t.Fatalf("expected error to mention the HTTP/2 stream error, got: %v", resp.Err())
	}
}
