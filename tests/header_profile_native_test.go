package surf_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	stdhttp "net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

type nativeHeaderCase struct {
	Method, Path string
	Headers      [][2]string
	Body         string            `json:"body_base64"`
	AcceptCH     string            `json:"accept_ch"`
	Available    map[string]string `json:"available_hints"`
}

// Native non-UA metric values are supplied as available identity/document data,
// then negotiated through the real origin cache. They are not copied directly
// onto the tested fetch request to conceal a missing negotiation or layout step.
func TestHeaderProfileNativeClientHintMetricsOnWire(t *testing.T) {
	fixture := readNativeHeaders(t, "chrome-metrics")
	for _, major := range []int{1, 2, 3} {
		for _, ref := range fixture.Requests {
			t.Run(fmt.Sprintf("http%d/%s%s", major, ref.Method, ref.Path), func(t *testing.T) {
				origin, captured := newProfileWirePeer(t, major, http.Header{header.ACCEPT_CH: {ref.AcceptCH}})
				b := surf.NewClient().Builder().Proxy("").Impersonate().MacOS().Chrome().Timeout(10 * time.Second)
				switch major {
				case 1:
					b.ForceHTTP1()
				case 2:
					b.ForceHTTP2()
				case 3:
					b.ForceHTTP3()
				}
				for name, value := range ref.Available {
					b.ClientHints().Value(name, value).Set()
				}
				c := b.Build().Unwrap()
				defer c.Close()
				ownershipDo(t, c.Get(g.String(origin+"/prime")))
				select {
				case <-captured:
				case <-time.After(5 * time.Second):
					t.Fatal("missing hint opt-in navigation")
				}
				require.NotEmpty(t, c.ClientHintNames(g.String(origin)), "server opt-in was learned")
				for _, standard := range []bool{false, true} {
					body, err := base64.StdEncoding.DecodeString(ref.Body)
					require.NoError(t, err)
					var reader io.Reader
					if len(body) > 0 {
						reader = bytes.NewReader(body)
					}
					fields := nativeInputFields(ref, origin)
					before := fields.Clone()
					var responseBody io.ReadCloser
					if standard {
						req, err := stdhttp.NewRequest(ref.Method, origin+ref.Path, reader)
						require.NoError(t, err)
						req.Header = stdhttp.Header(fields)
						response, err := c.Std().Do(req)
						require.NoError(t, err)
						responseBody = response.Body
					} else {
						req, err := http.NewRequest(ref.Method, origin+ref.Path, reader)
						require.NoError(t, err)
						req.Header = fields
						response, err := c.GetClient().Do(req)
						require.NoError(t, err)
						responseBody = response.Body
					}
					_, err = io.Copy(io.Discard, responseBody)
					require.NoError(t, err)
					require.NoError(t, responseBody.Close())
					var observed profileWireCapture
					select {
					case observed = <-captured:
					case <-time.After(5 * time.Second):
						t.Fatal("missing negotiated fetch request")
					}
					require.Equal(t, expectedNativeFields(ref, "chrome", origin, major), observed.fields, "all fields and their order, std=%v", standard)
					require.Equal(t, string(body), observed.body)
					require.Equal(t, before, fields, "hint insertion and ordering preserve application input")
				}
			})
		}
	}
}

type nativeHeaderFixture struct {
	Browser  string
	Requests []nativeHeaderCase
}

func readNativeHeaders(t *testing.T, browser string) nativeHeaderFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/wire/header_presets/" + browser + ".json")
	require.NoError(t, err)
	var f nativeHeaderFixture
	require.NoError(t, json.Unmarshal(data, &f))
	return f
}
func nativeInputFields(r nativeHeaderCase, origin string) http.Header {
	fields := make(http.Header)
	// These are application/document facts, not profile defaults. Do not copy
	// Accept/UA/cache/connection/encoding/ordinary Priority from the native oracle.
	for _, field := range r.Headers {
		name := strings.ToLower(field[0])
		value := strings.ReplaceAll(field[1], "<ORIGIN>", origin)
		if slices.Contains([]string{header.CONTENT_TYPE, header.ORIGIN, header.REFERER, header.SEC_FETCH_MODE, header.SEC_FETCH_DEST, header.SEC_FETCH_SITE, header.SEC_FETCH_USER, header.SEC_CH_UA}, name) {
			fields.Set(name, value)
		}
		if name == header.PRIORITY && strings.HasPrefix(r.Path, "/fetch-click/") {
			fields.Set(name, value)
		}
	}
	if _, present := fields[http.CanonicalHeaderKey(header.SEC_FETCH_USER)]; !present {
		fields[http.CanonicalHeaderKey(header.SEC_FETCH_USER)] = nil
	}
	return fields
}
func expectedNativeFields(r nativeHeaderCase, browser, origin string, major int) [][2]string {
	u, _ := url.Parse(origin)
	var fields [][2]string
	if major != 1 {
		values := map[string]string{":method": r.Method, ":authority": u.Host, ":scheme": u.Scheme, ":path": r.Path}
		order := []string{":method", ":authority", ":scheme", ":path"}
		if browser == "firefox" {
			order = []string{":method", ":path", ":authority", ":scheme"}
			if major == 3 {
				order = []string{":method", ":scheme", ":authority", ":path"}
			}
		}
		for _, name := range order {
			fields = append(fields, [2]string{name, values[name]})
		}
	}
	for _, field := range r.Headers {
		name := strings.ToLower(field[0])
		if major != 1 && (name == header.HOST || name == header.CONNECTION) {
			continue
		}
		if name == header.HOST {
			field[1] = u.Host
		} else {
			field[1] = strings.ReplaceAll(field[1], "<ORIGIN>", origin)
		}
		if major != 1 {
			field[0] = name
		}
		fields = append(fields, field)
		if browser == "firefox" && major == 3 && name == header.ACCEPT_ENCODING {
			fields = append(fields, [2]string{header.ALT_USED, u.Host})
		}
	}
	if major != 1 && browser == "chrome" {
		mode := ""
		for _, f := range r.Headers {
			if strings.EqualFold(f[0], header.SEC_FETCH_MODE) {
				mode = f[1]
			}
		}
		priority := "u=1, i"
		if mode == "navigate" {
			priority = "u=0, i"
		}
		fields = append(fields, [2]string{header.PRIORITY, priority})
	}
	if browser == "firefox" && major == 2 {
		fields = append(fields, [2]string{header.TE, "trailers"})
	}
	return fields
}

// Native H1 captures are independent full-field oracles. H2/H3 expectations
// apply only documented protocol deltas; these are local protocol regressions,
// not a claim of new native H2/H3 captures for every resource scenario.
func TestHeaderProfileNativeMethodsOnWire(t *testing.T) {
	for _, name := range []string{"chrome", "firefox", "chrome-insecure", "firefox-insecure"} {
		browser := strings.TrimSuffix(name, "-insecure")
		insecure := browser != name
		fixture := readNativeHeaders(t, name)
		protocols := []int{1, 2, 3}
		if insecure {
			protocols = []int{1} // Ordinary LAN HTTP uses HTTP/1, not cleartext H2/H3.
		}
		for _, major := range protocols {
			t.Run(fmt.Sprintf("%s/http%d", name, major), func(t *testing.T) {
				origin, captured := newProfileWirePeer(t, major, nil)
				im := surf.NewClient().Builder().Proxy("").Impersonate().MacOS()
				var b *surf.Builder
				if browser == "chrome" {
					b = im.Chrome()
				} else {
					b = im.Firefox()
				}
				switch major {
				case 1:
					b.ForceHTTP1()
				case 2:
					b.ForceHTTP2()
				case 3:
					b.ForceHTTP3()
				}
				if insecure {
					peer, err := url.Parse(origin)
					require.NoError(t, err)
					address := peer.Host
					// Route the untrusted logical host to our local byte peer. Trust
					// is determined from the URL, never from a resolver's answer.
					peer.Host = net.JoinHostPort("insecure.example", peer.Port())
					origin = peer.String()
					b.With(func(c *surf.Client) error {
						c.GetTransport().(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, network, address)
						}
						return nil
					}, 1)
					b.With(func(r *surf.Request) error { nativeRequestKind(r); return nil })
				}
				client := b.Timeout(10 * time.Second).Build().Unwrap()
				defer client.Close()
				for _, standard := range []bool{false, true} {
					for _, ref := range fixture.Requests {
						t.Run(fmt.Sprintf("std=%v/%s%s", standard, ref.Method, ref.Path), func(t *testing.T) {
							body, err := base64.StdEncoding.DecodeString(ref.Body)
							require.NoError(t, err)
							var reader io.Reader
							emptyUpload := slices.ContainsFunc(ref.Headers, func(f [2]string) bool { return strings.EqualFold(f[0], header.CONTENT_TYPE) }) && slices.ContainsFunc(ref.Headers, func(f [2]string) bool { return strings.EqualFold(f[0], header.CONTENT_LENGTH) && f[1] == "0" })
							if len(body) > 0 || emptyUpload {
								reader = bytes.NewReader(body)
							}
							fields := nativeInputFields(ref, origin)
							before := fields.Clone()
							var responseBody io.ReadCloser
							if standard {
								request, err := stdhttp.NewRequest(ref.Method, origin+ref.Path, reader)
								require.NoError(t, err)
								request.Header = stdhttp.Header(fields)
								response, err := client.Std().Do(request)
								require.NoError(t, err)
								responseBody = response.Body
							} else {
								request, err := http.NewRequest(ref.Method, origin+ref.Path, reader)
								require.NoError(t, err)
								request.Header = fields
								if insecure {
									wrapped := client.Get(g.String(origin + ref.Path))
									*wrapped.GetRequest() = *request
									result := wrapped.Do()
									require.False(t, result.IsErr(), "%v", result.Err())
									responseBody = result.Unwrap().GetResponse().Body
								} else {
									response, err := client.GetClient().Do(request)
									require.NoError(t, err)
									responseBody = response.Body
								}
							}
							_, err = io.Copy(io.Discard, responseBody)
							require.NoError(t, err)
							require.NoError(t, responseBody.Close())
							var observed profileWireCapture
							select {
							case observed = <-captured:
							case <-time.After(5 * time.Second):
								t.Fatal("missing wire request")
							}
							require.Equal(t, expectedNativeFields(ref, browser, origin, major), observed.fields, "entire field section, values, casing and order")
							require.Equal(t, string(body), observed.body)
							require.Equal(t, before, fields, "profile defaults must not mutate the caller's request")
						})
					}
				}
			})
		}
	}
}

// Request kind is a capture action/document fact. On insecure HTTP the browser
// omits Fetch Metadata, so those headers cannot double as the scenario selector.
func nativeRequestKind(r *surf.Request) {
	if strings.HasPrefix(r.GetRequest().URL.Path, "/fetch") || r.GetRequest().URL.Path == "/post" {
		r.Fetch()
	} else {
		r.Navigation()
	}
}

func TestHeaderContextScenarioAndUpload(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect, "CUSTOM"} {
		t.Run(method, func(t *testing.T) {
			r := &http.Request{Method: method, Header: make(http.Header)}
			c := profiles.HeaderContext{Request: r}
			require.Equal(t, method == http.MethodGet || method == http.MethodHead, c.Navigation())
			c.Kind = profiles.FetchRequest
			require.False(t, c.Navigation())
			c.Kind = profiles.NavigationRequest
			require.True(t, c.Navigation())
			require.False(t, c.HasBody())
			r.Header["sEc-FeTcH-mOdE"] = []string{"navigate"}
			require.True(t, c.Navigation())
			r.Header["sEc-FeTcH-mOdE"] = []string{"cors"}
			require.False(t, c.Navigation())
			r.GetBody = func() (io.ReadCloser, error) { t.Fatal("profile read a body"); return nil, nil }
			require.True(t, c.HasBody())
		})
	}
	require.True(t, (profiles.HeaderContext{}).Navigation())
	require.False(t, (profiles.HeaderContext{}).HasBody())
}

func TestHeaderProfileNativeRedirectsOnWire(t *testing.T) {
	fixture := readNativeHeaders(t, "chrome-redirect")
	for _, major := range []int{1, 2, 3} {
		for _, standard := range []bool{false, true} {
			for i, first := range fixture.Requests {
				if first.Method != http.MethodPost || i+1 == len(fixture.Requests) {
					continue
				}
				last := fixture.Requests[i+1]
				t.Run(fmt.Sprintf("http%d/std=%v%s", major, standard, first.Path), func(t *testing.T) {
					origin, captured := newProfileWirePeer(t, major, nil)
					b := surf.NewClient().Builder().Proxy("").Impersonate().MacOS().Chrome().Timeout(10 * time.Second)
					switch major {
					case 1:
						b.ForceHTTP1()
					case 2:
						b.ForceHTTP2()
					case 3:
						b.ForceHTTP3()
					}
					b.With(func(c *surf.Client) error {
						base := c.GetClient().Transport
						c.GetClient().Transport = hintRoundTrip(func(req *http.Request) (*http.Response, error) {
							resp, err := base.RoundTrip(req)
							if err == nil && req.URL.RequestURI() == first.Path {
								resp.StatusCode = 302
								resp.Status = "302 Found"
								resp.Header.Set("Location", origin+last.Path)
							}
							return resp, err
						})
						return nil
					}, math.MaxInt)
					client := b.Build().Unwrap()
					defer client.Close()
					body, err := base64.StdEncoding.DecodeString(first.Body)
					require.NoError(t, err)
					fields := nativeInputFields(first, origin)
					if standard {
						request, err := stdhttp.NewRequest(first.Method, origin+first.Path, bytes.NewReader(body))
						require.NoError(t, err)
						request.Header = stdhttp.Header(fields)
						response, err := client.Std().Do(request)
						require.NoError(t, err)
						_, err = io.Copy(io.Discard, response.Body)
						require.NoError(t, err)
						response.Body.Close()
					} else {
						request, err := http.NewRequest(first.Method, origin+first.Path, bytes.NewReader(body))
						require.NoError(t, err)
						request.Header = fields
						response, err := client.GetClient().Do(request)
						require.NoError(t, err)
						_, err = io.Copy(io.Discard, response.Body)
						require.NoError(t, err)
						response.Body.Close()
					}
					for _, reference := range []nativeHeaderCase{first, last} {
						var observed profileWireCapture
						select {
						case observed = <-captured:
						case <-time.After(5 * time.Second):
							t.Fatal("missing redirect wire request")
						}
						require.Equal(t, expectedNativeFields(reference, "chrome", origin, major), observed.fields, "complete redirect field list")
						expectedBody, err := base64.StdEncoding.DecodeString(reference.Body)
						require.NoError(t, err)
						require.Equal(t, string(expectedBody), observed.body)
					}
				})
			}
		}
	}
}
