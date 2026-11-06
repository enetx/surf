package surf_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestRequestBodyReplay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body func() any
		want string
	}{
		{"string", func() any { return "payload" }, "payload"},
		{"g_string", func() any { return g.String("payload") }, "payload"},
		{"bytes", func() any { return []byte("payload") }, "payload"},
		{"g_bytes", func() any { return g.Bytes("payload") }, "payload"},
		{"bytes_reader", func() any { r := bytes.NewReader([]byte("prefixpayload")); _, _ = r.Seek(6, io.SeekStart); return r }, "payload"},
		{"strings_reader", func() any { r := strings.NewReader("prefixpayload"); _, _ = r.Seek(6, io.SeekStart); return r }, "payload"},
		{"bytes_buffer", func() any { b := bytes.NewBufferString("prefixpayload"); b.Next(6); return b }, "payload"},
		{"form", func() any { return map[string]string{"a": "b"} }, "a=b"},
		{"json", func() any {
			return struct {
				Value string `json:"value"`
			}{"payload"}
		}, `{"value":"payload"}` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := surf.NewClient().Post("https://example.invalid/").Body(tc.body()).GetRequest()
			if request.GetBody == nil {
				t.Fatal("missing GetBody")
			}
			if request.ContentLength != int64(len(tc.want)) {
				t.Fatalf("wrong ContentLength: %d", request.ContentLength)
			}
			for range 2 {
				body, err := request.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(body)
				body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != tc.want {
					t.Fatalf("replay body=%q, want %q", data, tc.want)
				}
			}
			original, err := io.ReadAll(request.Body)
			request.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if string(original) != tc.want {
				t.Fatalf("GetBody changed original body: %q", original)
			}
		})
	}
}

func TestReplacingRequestBodyReplacesReplay(t *testing.T) {
	t.Parallel()
	t.Run("stream clears old replay", func(t *testing.T) {
		request := surf.NewClient().Post("https://example.invalid/").Body("old").Body(io.NopCloser(strings.NewReader("new"))).GetRequest()
		if request.GetBody != nil {
			t.Fatal("stream retained GetBody from old body")
		}
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "new" {
			t.Fatalf("body=%q", body)
		}
	})
	t.Run("in memory replacement", func(t *testing.T) {
		request := surf.NewClient().Post("https://example.invalid/").Body("old").Body(bytes.NewBufferString("new")).GetRequest()
		body, err := request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(body)
		body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "new" {
			t.Fatalf("replay=%q", data)
		}
	})
	t.Run("empty body", func(t *testing.T) {
		request := surf.NewClient().Post("https://example.invalid/").Body("old").Body("").GetRequest()
		if request.Body != http.NoBody || request.ContentLength != 0 || request.GetBody != nil {
			t.Fatal("empty body retained old body or replay")
		}
	})
}

func TestRequestBodyReplayOnTemporaryRedirect(t *testing.T) {
	t.Parallel()
	for _, payload := range []string{"payload", ""} {
		t.Run(payload, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					w.Header().Set("Location", "/target")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read redirected body: %v", err)
					return
				}
				if r.Method != http.MethodPost {
					t.Errorf("redirected method=%s", r.Method)
				}
				_, _ = w.Write(body)
			}))
			defer ts.Close()
			response := surf.NewClient().Post(g.String(ts.URL + "/start")).Body(payload).Do()
			if response.IsErr() {
				t.Fatal(response.Err())
			}
			if response.Ok().StatusCode != http.StatusOK {
				t.Fatalf("expected redirect to complete, got %d", response.Ok().StatusCode)
			}
			body := response.Ok().Body.String()
			if body.IsErr() || body.Ok().Std() != payload {
				t.Fatalf("redirect changed body: %v, err=%v", body, body.Err())
			}
		})
	}
}
