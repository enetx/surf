package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type streamBodyCloseSpy struct {
	io.ReadCloser
	closes atomic.Int32
}

func (b *streamBodyCloseSpy) Close() error { b.closes.Add(1); return b.ReadCloser.Close() }

func streamingClientServer(t *testing.T, protocol int, handler http.Handler, configure ...func(*surf.Builder)) (*surf.Client, string) {
	t.Helper()
	b := surf.NewClient().Builder().Timeout(5 * time.Second)
	var origin string
	switch protocol {
	case 1, 2:
		server := httptest.NewUnstartedServer(handler)
		if protocol == 2 {
			server.EnableHTTP2 = true
			server.StartTLS()
			b.ForceHTTP2().TLSConfig(&tls.Config{InsecureSkipVerify: true})
		} else {
			server.Start()
			b.ForceHTTP1()
		}
		t.Cleanup(server.Close)
		origin = server.URL
	case 3:
		cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		certs := cert.TLS.Certificates
		cert.Close()
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		server := &http3.Server{TLSConfig: &tls.Config{Certificates: certs}, Handler: handler}
		go server.Serve(socket)
		t.Cleanup(func() { server.Close(); socket.Close() })
		origin = "https://" + socket.LocalAddr().String()
		b.ForceHTTP3().HTTP3Settings().Set().TLSConfig(&tls.Config{InsecureSkipVerify: true})
	}
	for _, apply := range configure {
		apply(b)
	}
	client := b.Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	return client, origin
}

func TestStreamingBodyStartsBeforeEOF(t *testing.T) {
	for _, protocol := range []int{1, 2, 3} {
		for _, known := range []bool{false, true} {
			t.Run(fmt.Sprintf("http%d/known=%t", protocol, known), func(t *testing.T) {
				first := make(chan int64, 1)
				serverErr := make(chan error, 1)
				client, origin := streamingClientServer(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					prefix := make([]byte, 5)
					_, err := io.ReadFull(r.Body, prefix)
					if err != nil {
						serverErr <- err
						return
					}
					if string(prefix) != "first" {
						serverErr <- fmt.Errorf("prefix %q", prefix)
						return
					}
					first <- r.ContentLength
					rest, err := io.ReadAll(r.Body)
					if err != nil {
						serverErr <- err
						return
					}
					io.WriteString(w, string(prefix)+string(rest))
				}))
				reader, writer := io.Pipe()
				defer writer.CloseWithError(context.Canceled)
				spy := &streamBodyCloseSpy{ReadCloser: reader}
				req := client.Post(g.String(origin))
				if known {
					req.StreamingBody(spy, 9)
				} else {
					req.StreamingBody(spy)
				}
				type result struct {
					body string
					err  error
				}
				done := make(chan result, 1)
				go func() {
					rsp := req.Do()
					if rsp.IsErr() {
						done <- result{err: rsp.Err()}
						return
					}
					body := rsp.Ok().Body.String()
					done <- result{body: body.Ok().Std(), err: body.Err()}
				}()
				_, err := writer.Write([]byte("first"))
				require.NoError(t, err)
				select {
				case length := <-first:
					if known {
						require.EqualValues(t, 9, length)
					} else {
						require.EqualValues(t, -1, length)
					}
				case err := <-serverErr:
					t.Fatal(err)
				case <-time.After(3 * time.Second):
					t.Fatal("body was buffered until EOF before being sent")
				}
				_, err = writer.Write([]byte("rest"))
				require.NoError(t, err)
				require.NoError(t, writer.Close())
				select {
				case result := <-done:
					require.NoError(t, result.err)
					require.Equal(t, "firstrest", result.body)
				case <-time.After(5 * time.Second):
					t.Fatal("stream did not complete")
				}
				require.Eventually(t, func() bool { return spy.closes.Load() == 1 }, time.Second, time.Millisecond)
			})
		}
	}
}

func TestStreamingBodyStatusRetries(t *testing.T) {
	for _, protocol := range []int{1, 2, 3} {
		for _, replay := range []bool{false, true} {
			t.Run(fmt.Sprintf("http%d/replay=%t", protocol, replay), func(t *testing.T) {
				var calls, opens, closes atomic.Int32
				client, origin := streamingClientServer(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("read: %v", err)
						return
					}
					if string(body) != "payload" {
						t.Errorf("body=%q", body)
					}
					if calls.Add(1) == 1 {
						w.WriteHeader(503)
					}
					io.WriteString(w, "reply")
				}), func(b *surf.Builder) { b.Retry(1, 0, 503) })
				req := client.Post(g.String(origin))
				factory := func() (io.ReadCloser, error) {
					opens.Add(1)
					return &countedStreamingBody{Reader: strings.NewReader("payload"), close: func() { closes.Add(1) }}, nil
				}
				if replay {
					req.StreamingBodyFactory(factory, 7)
				} else {
					body, _ := factory()
					req.StreamingBody(body, 7)
				}
				rsp := req.Do()
				require.False(t, rsp.IsErr(), "%v", rsp.Err())
				rsp.Ok().Body.String().Unwrap()
				want := int32(1)
				status := 503
				if replay {
					want = 2
					status = 200
				}
				require.EqualValues(t, status, rsp.Ok().StatusCode)
				require.Equal(t, want, calls.Load())
				require.Equal(t, want, opens.Load())
				require.Eventually(t, func() bool { return closes.Load() == want }, time.Second, time.Millisecond)
			})
		}
	}
}

type countedStreamingBody struct {
	io.Reader
	close func()
}

func (b *countedStreamingBody) Close() error { b.close(); return nil }

func TestStreamingBodyRedirects(t *testing.T) {
	for _, code := range []int{307, 308} {
		for _, replay := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/replay=%t", code, replay), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					if r.URL.Path == "/start" {
						w.Header().Set("Location", "/end")
						w.WriteHeader(code)
						return
					}
					require.Equal(t, "POST", r.Method)
					io.WriteString(w, string(body))
				}))
				defer server.Close()
				client := surf.NewClient()
				defer client.Close()
				req := client.Post(g.String(server.URL + "/start"))
				if replay {
					req.StreamingBodyFactory(func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("payload")), nil }, 7)
				} else {
					req.StreamingBody(strings.NewReader("payload"), 7)
				}
				rsp := req.Do()
				require.False(t, rsp.IsErr(), "%v", rsp.Err())
				body := rsp.Ok().Body.String().Unwrap()
				if replay {
					require.EqualValues(t, 200, rsp.Ok().StatusCode)
					require.Equal(t, g.String("payload"), body)
					require.EqualValues(t, 2, calls.Load())
				} else {
					require.EqualValues(t, code, rsp.Ok().StatusCode)
					require.EqualValues(t, 1, calls.Load())
				}
			})
		}
	}
}

func TestStreamingBodyFactoryValidationAndReplacement(t *testing.T) {
	require.True(t, surf.NewClient().Post("https://example.invalid").StreamingBody(nil).Do().IsErr())
	require.True(t, surf.NewClient().Post("https://example.invalid").StreamingBody(strings.NewReader("x"), -2).Do().IsErr())
	require.True(t, surf.NewClient().Post("https://example.invalid").StreamingBody(strings.NewReader("x"), 1, 2).Do().IsErr())
	require.True(t, surf.NewClient().Post("https://example.invalid").StreamingBodyFactory(nil).Do().IsErr())
	var calls atomic.Int32
	req := surf.NewClient().Post("https://example.invalid").StreamingBodyFactory(func() (io.ReadCloser, error) { calls.Add(1); return nil, errors.New("open failed") })
	require.Zero(t, calls.Load())
	require.ErrorContains(t, req.Do().Err(), "open failed")
	require.EqualValues(t, 1, calls.Load())
	req = surf.NewClient().Post("https://example.invalid").StreamingBodyFactory(func() (io.ReadCloser, error) { return nil, nil })
	require.ErrorContains(t, req.Do().Err(), "returned nil")
	spy := &streamBodyCloseSpy{ReadCloser: io.NopCloser(strings.NewReader("stream"))}
	req = surf.NewClient().Post("https://example.invalid").StreamingBody(spy).Body("buffered")
	require.EqualValues(t, 1, spy.closes.Load())
	require.NotNil(t, req.GetRequest().GetBody)
	body, err := req.GetRequest().GetBody()
	require.NoError(t, err)
	data, err := io.ReadAll(body)
	body.Close()
	require.NoError(t, err)
	require.Equal(t, "buffered", string(data))
	req = surf.NewClient().Post("https://example.invalid").Body("buffered").StreamingBody(strings.NewReader("stream"))
	require.Nil(t, req.GetRequest().GetBody)
	require.EqualValues(t, -1, req.GetRequest().ContentLength)
	req = surf.NewClient().Post("https://example.invalid").StreamingBodyFactory(func() (io.ReadCloser, error) { t.Error("zero-length factory was called"); return nil, nil }, 0)
	require.Equal(t, http.NoBody, req.GetRequest().Body)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req = surf.NewClient().Post("https://example.invalid").StreamingBodyFactory(func() (io.ReadCloser, error) { t.Error("canceled factory was called"); return nil, nil }).WithContext(ctx)
	require.ErrorIs(t, req.Do().Err(), context.Canceled)
}

func TestStreamingBodyFactoryRetryFailure(t *testing.T) {
	var opens, closes atomic.Int32
	client, origin := streamingClientServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); w.WriteHeader(503) }), func(b *surf.Builder) { b.Retry(1, 0, 503) })
	rsp := client.Post(g.String(origin)).StreamingBodyFactory(func() (io.ReadCloser, error) {
		if opens.Add(1) > 1 {
			return nil, errors.New("reopen failed")
		}
		return &countedStreamingBody{Reader: strings.NewReader("payload"), close: func() { closes.Add(1) }}, nil
	}, 7).Do()
	require.ErrorContains(t, rsp.Err(), "reopen failed")
	require.EqualValues(t, 2, opens.Load())
	require.Eventually(t, func() bool { return closes.Load() == 1 }, time.Second, time.Millisecond)
}

func TestStreamingBodyHTTP3Fallback(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint(replay), func(t *testing.T) {
			var received, opens, closes atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				io.WriteString(w, string(body))
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			b := surf.NewClient().Builder().ForceHTTP3().Timeout(3 * time.Second)
			b.QUICSettings().HandshakeIdleTimeout(50 * time.Millisecond).Set()
			client := b.HTTP3Settings().Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Build().Unwrap()
			defer client.Close()
			factory := func() (io.ReadCloser, error) {
				opens.Add(1)
				return &countedStreamingBody{Reader: strings.NewReader("payload"), close: func() { closes.Add(1) }}, nil
			}
			req := client.Post(g.String(server.URL))
			if replay {
				req.StreamingBodyFactory(factory, 7)
			} else {
				body, _ := factory()
				req.StreamingBody(body, 7)
			}
			rsp := req.Do()
			if replay {
				require.False(t, rsp.IsErr(), "%v", rsp.Err())
				require.Equal(t, g.String("payload"), rsp.Ok().Body.String().Unwrap())
				require.Equal(t, 2, rsp.Ok().GetResponse().ProtoMajor)
				require.EqualValues(t, 1, received.Load())
				require.EqualValues(t, 2, opens.Load())
			} else {
				require.True(t, rsp.IsErr())
				require.ErrorContains(t, rsp.Err(), "GetBody is nil")
				require.Zero(t, received.Load())
				require.EqualValues(t, 1, opens.Load())
			}
			require.Eventually(t, func() bool { return closes.Load() == opens.Load() }, time.Second, time.Millisecond)
		})
	}
}

func TestStreamingBodyCancellationAfterHeaders(t *testing.T) {
	ready := make(chan struct{}, 1)
	client, origin := streamingClientServer(t, 3, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		ready <- struct{}{}
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	spy := &streamBodyCloseSpy{ReadCloser: reader}
	rsp := client.Post(g.String(origin)).StreamingBody(spy).WithContext(ctx).Do()
	require.False(t, rsp.IsErr(), "%v", rsp.Err())
	<-ready
	cancel()
	require.Eventually(t, func() bool { return spy.closes.Load() == 1 }, time.Second, time.Millisecond)
	rsp.Ok().Body.Close()
}

func TestStreamingBodySetupFailureClosesReader(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint(replay), func(t *testing.T) {
			failure := errors.New("request middleware failed")
			client := surf.NewClient().Builder().With(func(*surf.Request) error { return failure }).Build().Unwrap()
			defer client.Close()
			spy := &streamBodyCloseSpy{ReadCloser: io.NopCloser(strings.NewReader("payload"))}
			req := client.Post("https://example.invalid")
			if replay {
				req.StreamingBodyFactory(func() (io.ReadCloser, error) { return spy, nil })
			} else {
				req.StreamingBody(spy)
			}
			require.ErrorIs(t, req.Do().Err(), failure)
			require.EqualValues(t, 1, spy.closes.Load())
		})
	}
}

func TestStreamingBodyFactoryClosesReaderReturnedWithError(t *testing.T) {
	spy := &streamBodyCloseSpy{ReadCloser: io.NopCloser(strings.NewReader("payload"))}
	failure := errors.New("open partially failed")
	client := surf.NewClient()
	defer client.Close()
	result := client.Post("https://example.invalid").StreamingBodyFactory(func() (io.ReadCloser, error) {
		return spy, failure
	}).Do()
	require.ErrorIs(t, result.Err(), failure)
	require.EqualValues(t, 1, spy.closes.Load())
}
