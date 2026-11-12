package surf_test

import (
	"context"
	"errors"
	"io"
	"math"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/cookiejar"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/stretchr/testify/require"
)

type hintRoundTrip func(*http.Request) (*http.Response, error)

func (f hintRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func hintResponse(r *http.Request, fields http.Header) *http.Response {
	return &http.Response{StatusCode: 200, Status: "200 OK", Header: fields, Body: io.NopCloser(strings.NewReader("ok")), Request: r}
}
func hintClient(t *testing.T, configure func(*surf.Builder), trip hintRoundTrip) *surf.Client {
	t.Helper()
	b := surf.NewClient().Builder().Proxy("")
	b.ClientHints().Architecture("x86").Bitness("64").Set()
	if configure != nil {
		configure(b)
	}
	b.With(func(c *surf.Client) error { c.GetClient().Transport = trip; return nil }, math.MaxInt)
	c := b.Build().Unwrap()
	t.Cleanup(func() { c.Close() })
	return c
}
func hintRequest(t *testing.T, c *surf.Client, target string, fields http.Header) *http.Response {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	r.Header.Set(header.SEC_FETCH_MODE, "navigate")
	r.Header.Set(header.SEC_FETCH_DEST, "document")
	for k, v := range fields {
		r.Header[k] = slices.Clone(v)
	}
	response, err := c.GetClient().Do(r)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return response
}
func TestClientHintsNegotiationAndCriticalRestart(t *testing.T) {
	t.Parallel()
	var requests []*http.Request
	c := hintClient(t, nil, func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r)
		return hintResponse(r, http.Header{"Accept-Ch": {"Sec-CH-UA-Arch, Sec-CH-UA-Bitness"}, "Critical-Ch": {"sec-ch-ua-arch"}}), nil
	})
	hintRequest(t, c, "https://a.example/", nil)
	require.Len(t, requests, 2)
	require.Empty(t, requests[0].Header.Get(header.SEC_CH_UA_ARCH))
	require.Equal(t, `"x86"`, requests[1].Header.Get(header.SEC_CH_UA_ARCH))
	require.Equal(t, `"64"`, requests[1].Header.Get(header.SEC_CH_UA_BITNESS))
	hintRequest(t, c, "https://a.example/next", nil)
	require.Len(t, requests, 3)
	hintRequest(t, c, "https://b.example/", nil)
	require.Len(t, requests, 5, "another origin needs its own negotiation")
	require.Empty(t, requests[3].Header.Get(header.SEC_CH_UA_ARCH))
	names := c.ClientHintNames("https://a.example/anything")
	require.Equal(t, []string{header.SEC_CH_UA_ARCH, header.SEC_CH_UA_BITNESS}, names)
	names[0] = "changed"
	require.Equal(t, header.SEC_CH_UA_ARCH, c.ClientHintNames("https://a.example/")[0])
	c.ClearClientHints()
	require.Empty(t, c.ClientHintNames("https://a.example/"))
}
func TestClientHintsAcceptCHStructuredFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, value string
		valid       bool
		names       []string
	}{
		{"simple", "Sec-CH-UA-Arch, sec-ch-ua-bitness", true, []string{header.SEC_CH_UA_ARCH, header.SEC_CH_UA_BITNESS}},
		{"parameters", `sec-ch-ua-bitness;a;b=?1;c="x\\y\"z";d=1.23;e=-123;f=:YWJj:;g=token`, true, []string{header.SEC_CH_UA_BITNESS}},
		{"empty", " \t ", true, nil}, {"unknown", "future-hint", true, nil},
		{"duplicates", "SEC-CH-UA-BITNESS, sec-ch-ua-bitness", true, []string{header.SEC_CH_UA_BITNESS}},
		{"trailing comma", "sec-ch-ua-bitness,", false, nil}, {"leading comma", ",sec-ch-ua-bitness", false, nil},
		{"string", `"sec-ch-ua-bitness"`, false, nil}, {"inner list", "(sec-ch-ua-bitness)", false, nil},
		{"number", "1", false, nil}, {"invalid member", "sec-ch-ua-bitness, ?1", false, nil},
		{"invalid parameter", "sec-ch-ua-bitness;A=1", false, nil},
		{"parameter missing value", "sec-ch-ua-bitness;a=", false, nil},
		{"bad escape", `sec-ch-ua-bitness;a="a\b"`, false, nil},
		{"unterminated string", `sec-ch-ua-bitness;a="`, false, nil},
		{"bad boolean", "sec-ch-ua-bitness;a=?2", false, nil},
		{"bad decimal", "sec-ch-ua-bitness;a=1.1234", false, nil},
		{"long integer", "sec-ch-ua-bitness;a=1234567890123456", false, nil},
		{"long decimal", "sec-ch-ua-bitness;a=1234567890123.1", false, nil},
		{"no digits", "sec-ch-ua-bitness;a=-", false, nil},
		{"empty fraction", "sec-ch-ua-bitness;a=1.", false, nil},
		{"bad base64", "sec-ch-ua-bitness;a=:!!!:", false, nil},
		{"unterminated bytes", "sec-ch-ua-bitness;a=:abc", false, nil},
		{"too large", strings.Repeat("a", 65537), false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := header.SEC_CH_UA_ARCH
			c := hintClient(t, nil, func(r *http.Request) (*http.Response, error) {
				return hintResponse(r, http.Header{"aCcEpT-cH": {value}}), nil
			})
			hintRequest(t, c, "https://example.com/", nil)
			value = tc.value
			hintRequest(t, c, "https://example.com/", nil)
			expected := tc.names
			if !tc.valid {
				expected = []string{header.SEC_CH_UA_ARCH}
			}
			require.Equal(t, expected, c.ClientHintNames("https://example.com/"))
		})
	}
}
func TestClientHintsCacheOriginsTrustAndLimits(t *testing.T) {
	t.Parallel()
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	c := hintClient(t, func(b *surf.Builder) {
		b.ClientHints().Capacity(2).Lifetime(time.Minute).Clock(func() time.Time { return time.Unix(0, now.Load()) }).Set()
	}, func(r *http.Request) (*http.Response, error) {
		return hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}}), nil
	})
	for _, target := range []string{"https://EXAMPLE.com:443/a", "https://other.example/"} {
		hintRequest(t, c, target, nil)
	}
	require.NotEmpty(t, c.ClientHintNames("https://example.com/next"))
	hintRequest(t, c, "https://third.example/", nil)
	require.Empty(t, c.ClientHintNames("https://other.example/"), "least recently used origin is evicted")
	require.Empty(t, c.ClientHintNames("https://example.com:444/"))
	require.Empty(t, c.ClientHintNames("http://example.com/"))
	now.Add(int64(time.Minute))
	require.Empty(t, c.ClientHintNames("https://example.com/"))
	for _, tc := range []struct {
		target  string
		trusted bool
	}{
		{"http://example.com/", false}, {"http://127.0.0.1/", true}, {"http://127.4.3.2/", true},
		{"http://[::1]/", true}, {"http://[::ffff:127.0.0.1]/", false}, {"http://localhost./", true}, {"http://a.localhost/", true},
		{"http://localhost.example/", false}, {"https://example.com/", true},
	} {
		t.Run(tc.target, func(t *testing.T) {
			hintRequest(t, c, tc.target, nil)
			require.Equal(t, tc.trusted, len(c.ClientHintNames(g.String(tc.target))) > 0)
		})
	}
	hintRequest(t, c, "https://bücher.example:0443/", nil)
	require.NotEmpty(t, c.ClientHintNames("https://xn--bcher-kva.example/"))
	require.Empty(t, c.ClientHintNames("://bad"))
	require.Empty(t, c.ClientHintNames("ftp://example.com/"))
}
func TestClientHintsCriticalConditions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, accept, critical string
		fields                 http.Header
		want                   int
	}{
		{"valid", header.SEC_CH_UA_ARCH, header.SEC_CH_UA_ARCH, nil, 2},
		{"no critical", header.SEC_CH_UA_ARCH, "", nil, 1},
		{"no accept", "", header.SEC_CH_UA_ARCH, nil, 1},
		{"not accepted", header.SEC_CH_UA_ARCH, header.SEC_CH_UA_BITNESS, nil, 1},
		{"unknown", "future", "future", nil, 1},
		{"low entropy", header.SEC_CH_UA, header.SEC_CH_UA, nil, 1},
		{"unavailable", "sec-ch-dpr", "sec-ch-dpr", nil, 1},
		{"bad accept", `"sec-ch-ua-arch"`, header.SEC_CH_UA_ARCH, nil, 1},
		{"bad critical", header.SEC_CH_UA_ARCH, `"sec-ch-ua-arch"`, nil, 1},
		{"explicit", header.SEC_CH_UA_ARCH, header.SEC_CH_UA_ARCH, http.Header{"sEc-Ch-Ua-ArCh": {`"arm"`}}, 1},
		{"explicit suppression", header.SEC_CH_UA_ARCH, header.SEC_CH_UA_ARCH, http.Header{"Sec-Ch-Ua-Arch": nil}, 1},
		{"fetch", header.SEC_CH_UA_ARCH, header.SEC_CH_UA_ARCH, http.Header{"Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			c := hintClient(t, nil, func(r *http.Request) (*http.Response, error) {
				count++
				return hintResponse(r, http.Header{"Accept-Ch": {tc.accept}, "Critical-Ch": {tc.critical}}), nil
			})
			hintRequest(t, c, "https://example.com/", tc.fields)
			require.Equal(t, tc.want, count)
			if tc.name == "fetch" {
				require.Empty(t, c.ClientHintNames("https://example.com/"))
			}
		})
	}
}
func TestClientHintsCriticalBodyCookiesAndFinalPolicy(t *testing.T) {
	t.Parallel()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	u, err := url.Parse("https://example.com/")
	require.NoError(t, err)
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "old"}})
	count := 0
	closed := &hintCloseBody{}
	c := hintClient(t, func(b *surf.Builder) { b.With(func(c *surf.Client) error { c.GetClient().Jar = jar; return nil }) }, func(r *http.Request) (*http.Response, error) {
		count++
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, "payload", string(body))
		r.Body.Close()
		if count == 1 {
			resp := hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}, "Critical-Ch": {header.SEC_CH_UA_ARCH}, "Set-Cookie": {"session=new; Path=/"}})
			resp.Body = closed
			return resp, nil
		}
		require.Equal(t, `"x86"`, r.Header.Get(header.SEC_CH_UA_ARCH))
		require.Equal(t, []*http.Cookie{{Name: "explicit", Value: "keep"}, {Name: "session", Value: "new"}}, r.Cookies())
		return hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_BITNESS}, "Critical-Ch": {header.SEC_CH_UA_BITNESS}}), nil
	})
	r, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader("payload"))
	require.NoError(t, err)
	r.Header.Set(header.SEC_FETCH_MODE, "navigate")
	r.Header.Set(header.SEC_FETCH_DEST, "document")
	r.AddCookie(&http.Cookie{Name: "explicit", Value: "keep"})
	resp, err := c.GetClient().Do(r)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 2, count)
	require.True(t, closed.closed.Load())
	require.Equal(t, []string{header.SEC_CH_UA_BITNESS}, c.ClientHintNames("https://example.com/"))
}

type hintCloseBody struct{ closed atomic.Bool }

func (*hintCloseBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *hintCloseBody) Close() error           { b.closed.Store(true); return nil }
func TestClientHintsBodyReplayFailuresAndCancellation(t *testing.T) {
	t.Parallel()
	failure := errors.New("factory failed")
	for _, mode := range []string{"stream", "factory error", "factory reader and error", "nil body", "canceled", "transport error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			closed := &hintCloseBody{}
			factoryBody := &hintCloseBody{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := hintClient(t, nil, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "transport error" {
					return nil, failure
				}
				r.Body.Close()
				resp := hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}, "Critical-Ch": {header.SEC_CH_UA_ARCH}})
				resp.Body = closed
				if mode == "canceled" {
					cancel()
				}
				return resp, nil
			})
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", io.NopCloser(strings.NewReader("body")))
			require.NoError(t, err)
			r.Header.Set(header.SEC_FETCH_MODE, "navigate")
			r.Header.Set(header.SEC_FETCH_DEST, "document")
			if mode == "factory error" {
				r.GetBody = func() (io.ReadCloser, error) { return nil, failure }
			}
			if mode == "factory reader and error" {
				r.GetBody = func() (io.ReadCloser, error) { return factoryBody, failure }
			}
			if mode == "nil body" {
				r.GetBody = func() (io.ReadCloser, error) { return nil, nil }
			}
			resp, err := c.GetClient().Do(r)
			if mode == "factory error" || mode == "factory reader and error" || mode == "nil body" || mode == "transport error" {
				require.Error(t, err)
				if mode != "nil body" {
					require.ErrorIs(t, err, failure)
				}
			} else {
				require.NoError(t, err)
				require.False(t, closed.closed.Load())
				resp.Body.Close()
			}
			if mode == "factory reader and error" {
				require.True(t, factoryBody.closed.Load())
				require.True(t, closed.closed.Load())
			}
			require.Equal(t, 1, calls)
		})
	}
}
func TestClientHintsConcurrentOrigins(t *testing.T) {
	t.Parallel()
	c := hintClient(t, nil, func(r *http.Request) (*http.Response, error) {
		return hintResponse(r, http.Header{"Accept-Ch": {header.SEC_CH_UA_ARCH}}), nil
	})
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			for range 10 {
				hintRequest(t, c, "https://"+g.Int(i).String().Std()+".example/", nil)
				c.ClientHintNames("https://0.example/")
			}
		})
	}
	wg.Wait()
	require.NotEmpty(t, c.ClientHintNames("https://0.example/"))
	c.ClearClientHints()
}
