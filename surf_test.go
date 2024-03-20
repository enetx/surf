package surf_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/enetx/surf"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http2"
	"github.com/enetx/http2/h2c"

	"github.com/andybalholm/brotli"
)

func TestH2C(t *testing.T) {
	t.Parallel()

	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello %s http == %v", r.Proto, r.TLS == nil)
	})

	ts := httptest.NewUnstartedServer(h2c.NewHandler(handler, h2s))
	ts.Start()

	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().H2C()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("Hello HTTP/2.0 http == true") {
		t.Error()
	}
}

func TestUnixDomainSocket(t *testing.T) {
	t.Parallel()

	const socketPath = "/tmp/surfecho.sock"

	os.Remove(socketPath) // remove if exist

	// Create a Unix domain socket and listen for incoming connections.
	socket, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Error(err)
		return
	}

	defer os.Remove(socketPath)

	ts := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("unix domain socket"))
		}),
	)

	// NewUnstartedServer creates a listener. Close that listener and replace
	// with the one we created.
	ts.Listener.Close()
	ts.Listener = socket
	ts.Start()

	defer ts.Close()

	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().UnixDomainSocket(socketPath)).
		Get("unix").
		Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("unix domain socket") {
		t.Error()
	}
}

func TestContenType(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, r.Header["Content-Type"])
		}),
	)

	defer ts.Close()

	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().ContentType("secret/content-type")).
		Get(ts.URL).
		Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("secret/content-type") {
		t.Error()
	}
}

func TestDisableKeepAlive(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, r.Header["Connection"])
		}),
	)

	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().DisableKeepAlive()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("close") {
		t.Error()
	}
}

func TestMultipart(t *testing.T) {
	t.Parallel()

	const (
		values = "values"
		some   = "some"
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(32 << 20)

		var buff bytes.Buffer
		if r.FormValue(some) == values {
			buff.WriteString(r.FormValue(some))
		}
		w.Write(buff.Bytes())
	}))
	defer ts.Close()

	multipartData := map[string]string{some: values}

	r, err := surf.NewClient().Multipart(ts.URL, multipartData).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if r.Body.String() != values {
		t.Error()
	}
}

func TestFileUpload(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(32 << 20)

		var buff bytes.Buffer
		if r.FormValue("some") == "values" {
			buff.WriteString(r.FormValue("some"))
		}

		file, _, _ := r.FormFile("file")
		defer file.Close()

		io.Copy(&buff, file)
		w.Write(buff.Bytes())
	}))
	defer ts.Close()

	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().CacheBody()).
		FileUpload(ts.URL, "file", "info.txt", "justfile").
		Do()
	if err != nil {
		t.Error(err)
		return
	}

	multipartValues := map[string]string{"some": "values"}

	r2, err := surf.NewClient().
		FileUpload(ts.URL, "file", "info.txt", "multipart", multipartValues).
		Do()
	if err != nil {
		t.Error(err)
		return
	}

	if r.Body.String() != "justfile" || r2.Body.String() != "valuesmultipart" {
		t.Error()
	}
}

func TestDeflate(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		buf := &bytes.Buffer{}
		w2 := zlib.NewWriter(buf)
		w2.Write([]byte("OK"))
		w2.Close()

		w.Header().Set("Content-Encoding", "deflate")
		w.Write(buf.Bytes())
	}))
	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().CacheBody()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") || !r.Body.Contains([]byte("OK")) {
		t.Error()
	}
}

func TestGzip(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		buf := &bytes.Buffer{}
		w2 := gzip.NewWriter(buf)
		w2.Write([]byte("OK"))
		w2.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	}))
	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().CacheBody()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") || !r.Body.Contains([]byte("OK")) {
		t.Error()
	}
}

func TestBrotli(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		buf := &bytes.Buffer{}
		w2 := brotli.NewWriter(buf)
		w2.Write([]byte("OK"))
		w2.Close()

		w.Header().Set("Content-Encoding", "br")
		w.Write(buf.Bytes())
	}))
	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().CacheBody()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") || !r.Body.Contains([]byte("OK")) {
		t.Error()
	}
}

func TestBody(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "OK")
	}))
	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().CacheBody()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") || !r.Body.Contains([]byte("OK")) {
		t.Error()
	}
}

func TestTimeOut(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(time.Nanosecond)
		io.WriteString(w, "OK")
	}))
	defer ts.Close()

	_, err := surf.NewClient().
		SetOptions(surf.NewOptions().Timeout(time.Microsecond)).
		Get(ts.URL).
		Do()
	r, _ := surf.NewClient().SetOptions(surf.NewOptions().Timeout(time.Second)).Get(ts.URL).Do()

	if err == nil || !r.Body.Contains("OK") {
		t.Error()
	}
}

func TestSession(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cookie http.Cookie

		cookies, err := r.Cookie("username")
		if err == http.ErrNoCookie {
			cookie = http.Cookie{Name: "username", Value: "root"}
		} else if cookies.Value == "root" {
			cookie = http.Cookie{Name: "username", Value: "toor"}
		}

		http.SetCookie(w, &cookie)
	}))
	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().Session()).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	r.Body.Close()

	r, err = r.Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	cookies := r.GetCookies(ts.URL)

	if !reflect.DeepEqual(cookies, []*http.Cookie{{Name: "username", Value: "toor"}}) {
		t.Error()
	}
}

func TestBearerAuth(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "Bearer "
		authHeader := r.Header.Get("Authorization")
		reqToken := strings.TrimPrefix(authHeader, prefix)

		if authHeader == "" || reqToken == authHeader {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		if reqToken != "good" {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}
	}))

	defer ts.Close()

	r, err := surf.NewClient().SetOptions(surf.NewOptions().BearerAuth("good")).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}
	defer r.Body.Close()

	r2, err := surf.NewClient().SetOptions(surf.NewOptions().BearerAuth("bad")).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}
	defer r2.Body.Close()

	if r.StatusCode != http.StatusOK || r2.StatusCode != http.StatusUnauthorized {
		t.Error()
	}
}

func TestBasicAuth(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		username, password, ok := r.BasicAuth()

		if !ok {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		if username != "good" || password != "password" {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}
	}))

	defer ts.Close()

	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().BasicAuth("good:password")).
		Get(ts.URL).
		Do()
	if err != nil {
		t.Error(err)
		return
	}
	defer r.Body.Close()

	r2, err := surf.NewClient().
		SetOptions(surf.NewOptions().BasicAuth("bad:password")).
		Get(ts.URL).
		Do()
	if err != nil {
		t.Error(err)
		return
	}
	defer r2.Body.Close()

	if r.StatusCode != http.StatusOK || r2.StatusCode != http.StatusUnauthorized {
		t.Error()
	}
}

func TestCookies(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("root"); err == nil {
			if cookie.Value == "cookie" {
				io.WriteString(w, "OK")
			}
		}
	}))
	defer ts.Close()

	c1 := &http.Cookie{Name: "root", Value: "cookie"}

	r, err := surf.NewClient().Get(ts.URL).AddCookies(c1).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") {
		t.Error()
	}
}

func TestUserAgent(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.UserAgent())
	}))
	defer ts.Close()

	agent := "Hi from surf"

	r, err := surf.NewClient().SetOptions(surf.NewOptions().UserAgent(agent)).Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains(agent) {
		t.Error()
	}
}

func TestHeaders(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		some := r.Header.Get("Some")
		if some == "header" {
			io.WriteString(w, "OK")
		}
	}))
	defer ts.Close()

	headers := map[string]string{"some": "header"}

	r, err := surf.NewClient().Get(ts.URL).AddHeaders(headers).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") {
		t.Error()
	}
}

func TestHTTP2(t *testing.T) {
	t.Parallel()

	ts := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, %s", r.Proto)
		}))
	ts.EnableHTTP2 = true
	ts.StartTLS()

	defer ts.Close()

	r, err := surf.NewClient().Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("Hello, HTTP/2.0") {
		t.Error()
	}
}

func TestGet(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "OK")
	}))
	defer ts.Close()

	r, err := surf.NewClient().Get(ts.URL).Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") {
		t.Error()
	}
}

func TestPost(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("test") == "data" {
			io.WriteString(w, "OK")
		}
	}))
	defer ts.Close()

	r, err := surf.NewClient().Post(ts.URL, "test=data").Do()
	if err != nil {
		t.Error(err)
		return
	}

	if !r.Body.Contains("OK") {
		t.Error()
	}
}
