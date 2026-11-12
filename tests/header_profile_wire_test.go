package surf_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

type profileWireCapture struct {
	fields      [][2]string
	body        string
	method      string
	path        string
	priority    http2.PriorityParam
	hasPriority bool
}

// newProfileWirePeer observes decoded wire fields before any server Header map
// can canonicalize names or discard their order. It responds only after reading
// the request body, including a complete HTTP/2 or HTTP/3 request stream.
func newProfileWirePeer(t *testing.T, major int, headers http.Header) (string, <-chan profileWireCapture) {
	t.Helper()
	captures := make(chan profileWireCapture, 32)
	if major == 3 {
		peer := startH3PeerWithBody(t, nil, nil, stdhttp.Header(headers))
		go func() {
			for {
				select {
				case request := <-peer.requests:
					capture := profileWireCapture{body: request.body}
					for _, field := range request.headers {
						capture.fields = append(capture.fields, [2]string{field.Name, field.Value})
						if field.Name == ":method" {
							capture.method = field.Value
						} else if field.Name == ":path" {
							capture.path = field.Value
						}
					}
					select {
					case captures <- capture:
					case <-t.Context().Done():
						return
					}
				case err := <-peer.errors:
					profileWirePeerError(t, err)
					return
				case <-t.Context().Done():
					return
				}
			}
		}()
		return peer.url, captures
	}

	responseHeaders := headers.Clone()
	if responseHeaders == nil {
		responseHeaders = make(http.Header)
	}
	responseHeaders.Set("Content-Length", "2")
	if major == 2 {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			profileWirePeerError(t, errors.New("HTTP/2 wire peer received an HTTP/1 request"))
		}))
		server.EnableHTTP2 = true
		server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
			"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
				defer conn.Close()
				if err := profileWireHTTP2(t, conn, responseHeaders, captures); err != nil {
					profileWirePeerError(t, err)
				}
			},
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.URL, captures
	}
	if major != 1 {
		t.Fatalf("unsupported wire peer protocol %d", major)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if err := profileWireHTTP1(t, conn, responseHeaders, captures); err != nil {
					profileWirePeerError(t, err)
				}
			}()
		}
	}()
	return "http://" + listener.Addr().String(), captures
}

func profileWirePeerError(t *testing.T, err error) {
	if err == nil || t.Context().Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	t.Errorf("profile wire peer: %v", err)
}

func profileWireHTTP1(t *testing.T, conn net.Conn, headers http.Header, captures chan<- profileWireCapture) error {
	reader := bufio.NewReader(conn)
	for {
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return fmt.Errorf("invalid request line %q", line)
		}
		capture := profileWireCapture{method: parts[0], path: parts[1]}
		var raw strings.Builder
		raw.WriteString(line)
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				return err
			}
			raw.WriteString(line)
			if line == "\r\n" || line == "\n" {
				break
			}
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				return fmt.Errorf("invalid header line %q", line)
			}
			capture.fields = append(capture.fields, [2]string{name, strings.Trim(value, " \t\r\n")})
		}
		// Reuse Go's body framing parser while retaining the independent raw
		// field capture above, including HTTP/1 casing and repeated fields.
		reader = bufio.NewReader(io.MultiReader(strings.NewReader(raw.String()), reader))
		request, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return err
		}
		if err := request.Body.Close(); err != nil {
			return err
		}
		capture.body = string(body)
		select {
		case captures <- capture:
		case <-t.Context().Done():
			return nil
		}
		var response bytes.Buffer
		response.WriteString("HTTP/1.1 200 OK\r\n")
		if err := headers.Write(&response, -1); err != nil {
			return err
		}
		response.WriteString("\r\n")
		if capture.method != http.MethodHead {
			response.WriteString("ok")
		}
		if _, err := conn.Write(response.Bytes()); err != nil {
			return err
		}
	}
}

func profileWireHTTP2(t *testing.T, conn net.Conn, headers http.Header, captures chan<- profileWireCapture) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("invalid HTTP/2 client preface %q", preface)
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(1<<20, nil)
	if err := framer.WriteSettings(); err != nil {
		return err
	}
	streams := make(map[uint32]*profileWireCapture)
	respond := func(streamID uint32) error {
		capture := streams[streamID]
		delete(streams, streamID)
		select {
		case captures <- *capture:
		case <-t.Context().Done():
			return nil
		}
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
		if err := encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
			return err
		}
		for name, values := range headers {
			for _, value := range values {
				if err := encoder.WriteField(hpack.HeaderField{Name: strings.ToLower(name), Value: value}); err != nil {
					return err
				}
			}
		}
		head := capture.method == http.MethodHead
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, EndHeaders: true, EndStream: head, BlockFragment: block.Bytes()}); err != nil {
			return err
		}
		if !head {
			return framer.WriteData(streamID, true, []byte("ok"))
		}
		return nil
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.PingFrame:
			if !frame.Flags.Has(http2.FlagPingAck) {
				if err := framer.WritePing(true, frame.Data); err != nil {
					return err
				}
			}
		case *http2.MetaHeadersFrame:
			capture := streams[frame.StreamID]
			if capture == nil {
				capture = &profileWireCapture{}
				streams[frame.StreamID] = capture
			}
			capture.priority = frame.Priority
			capture.hasPriority = frame.HasPriority()
			for _, field := range frame.Fields {
				capture.fields = append(capture.fields, [2]string{field.Name, field.Value})
				if field.Name == ":method" {
					capture.method = field.Value
				} else if field.Name == ":path" {
					capture.path = field.Value
				}
			}
			if frame.StreamEnded() {
				if err := respond(frame.StreamID); err != nil {
					return err
				}
			}
		case *http2.DataFrame:
			capture := streams[frame.StreamID]
			if capture == nil {
				return fmt.Errorf("DATA before HEADERS on stream %d", frame.StreamID)
			}
			capture.body += string(frame.Data())
			if n := frame.Header().Length; n > 0 {
				if err := framer.WriteWindowUpdate(0, n); err != nil {
					return err
				}
				if err := framer.WriteWindowUpdate(frame.StreamID, n); err != nil {
					return err
				}
			}
			if frame.StreamEnded() {
				if err := respond(frame.StreamID); err != nil {
					return err
				}
			}
		case *http2.RSTStreamFrame:
			delete(streams, frame.StreamID)
		case *http2.GoAwayFrame:
			return nil
		}
	}
}

func profileOrderClient(t *testing.T, browser, device string, major int) *surf.Client {
	t.Helper()
	b := surf.NewClient().Builder().Proxy("").Timeout(5 * time.Second)
	im := b.Impersonate()
	switch device {
	case "windows":
		im.Windows()
	case "macos":
		im.MacOS()
	case "linux":
		im.Linux()
	case "android":
		im.Android()
	case "ios":
		im.IOS()
	default:
		t.Fatalf("unknown device %q", device)
	}
	if browser == "chrome" {
		im.Chrome()
	} else {
		im.Firefox()
	}
	switch major {
	case 1:
		b.ForceHTTP1()
	case 2:
		b.ForceHTTP2()
	case 3:
		b.ForceHTTP3()
	}
	c := b.Build().Unwrap()
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

// These are application fields in an intentionally unusual order, independently
// of any browser factory. Known fields must not be promoted ahead of X-Wire;
// computed Host/Content-Length use their reserved slots and repeated values
// remain adjacent. Casing is explicitly owned by HeaderCaseKey on HTTP/1.
func profileOrderInput() [][2]string {
	return [][2]string{
		{"x-WiRe-Before", "before"},
		{"aCcEpT", "application/x-profile-wire"},
		{"content-LENGTH", ""},
		{"hOsT", ""},
		{"cOnNeCtIoN", "keep-alive"},
		{"uSeR-aGeNt", "profile-wire-agent"},
		{"x-MuLtI", "first"},
		{"cOoKiE", "first=1; second=2"},
		{"sEc-Ch-Ua", `"Wire";v="1"`},
		{"sEc-Ch-Ua-Mobile", "?0"},
		{"sEc-Ch-Ua-Platform", `"WireOS"`},
		{"sEc-Ch-Ua-Arch", `"wire-arch"`},
		{"sEc-Ch-Ua-Bitness", `"128"`},
		{"cOnTeNt-TyPe", "application/octet-stream"},
		{"aCcEpT-EnCoDiNg", "identity"},
		{"aCcEpT-LaNgUaGe", "zz"},
		{"sEc-FeTcH-MoDe", "cors"},
		{"sEc-FeTcH-DeSt", "empty"},
		{"sEc-FeTcH-SiTe", "same-origin"},
		{"oRiGiN", "https://wire.example"},
		{"rEfErEr", "https://wire.example/start"},
		{"aUtHoRiZaTiOn", "Bearer wire"},
		{"pRiOrItY", "u=6"},
		{"tE", "trailers"},
		{"aLt-UsEd", "wire.example"},
		{"cAcHe-CoNtRoL", "no-cache"},
		{"pRaGmA", "no-cache"},
		{"x-WiRe-After", "after"},
	}
}

func profileOrderRequest(t *testing.T, c *surf.Client, origin, method string, pseudo []string) (*surf.Request, string, string) {
	t.Helper()
	path := "/wire?method=" + method
	var req *surf.Request
	switch method {
	case http.MethodGet:
		req = c.Get(g.String(origin + path))
	case http.MethodHead:
		req = c.Head(g.String(origin + path))
	case http.MethodPost:
		req = c.Post(g.String(origin + path))
	case http.MethodPut:
		req = c.Put(g.String(origin + path))
	case http.MethodPatch:
		req = c.Patch(g.String(origin + path))
	case http.MethodDelete:
		req = c.Delete(g.String(origin + path))
	case http.MethodOptions:
		req = c.Options(g.String(origin + path))
	default:
		// TRACE and CONNECT exercise the generic raw API. Browser Fetch forbids
		// these methods; the tests make no native browser parity claim for them.
		u, err := url.Parse(origin)
		require.NoError(t, err)
		target := path
		if method == http.MethodConnect {
			target = u.Host
			path = ""
		}
		raw := method + " " + target + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n"
		req = c.Raw(g.String(raw), g.String(u.Scheme))
	}
	body := ""
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		body = "wire-body"
		req.Body(body)
	}
	ordered := g.NewMapOrd[string, string]()
	var casing []string
	for _, field := range profileOrderInput() {
		ordered.Insert(field[0], field[1])
		casing = append(casing, field[0])
	}
	req.SetHeaders(ordered).AddHeaders("x-MuLtI", "second")
	req.GetRequest().Header[http.HeaderCaseKey] = casing
	if pseudo != nil {
		req.GetRequest().Header[http.PHeaderOrderKey] = slices.Clone(pseudo)
	}
	return req, path, body
}

func profileOrderExpected(t *testing.T, origin, browser, device, method, path, body string, major int, pseudo []string) [][2]string {
	t.Helper()
	u, err := url.Parse(origin)
	require.NoError(t, err)
	var fields [][2]string
	if major != 1 {
		if pseudo == nil {
			// Independent protocol defaults. Mobile placeholders retain their
			// existing shapes; the matrix checks supported API behavior only.
			switch {
			case browser == "chrome" && device != "ios":
				pseudo = []string{":method", ":authority", ":scheme", ":path"}
			case browser == "chrome" || major == 3:
				pseudo = []string{":method", ":scheme", ":authority", ":path"}
			default:
				pseudo = []string{":method", ":path", ":authority", ":scheme"}
			}
		}
		for _, name := range pseudo {
			var value string
			switch name {
			case ":method":
				value = method
			case ":authority":
				value = u.Host
			case ":scheme":
				if method == http.MethodConnect {
					continue
				}
				value = u.Scheme
			case ":path":
				if method == http.MethodConnect {
					continue
				}
				value = path
			}
			fields = append(fields, [2]string{name, value})
		}
	}
	for _, field := range profileOrderInput() {
		name, value := field[0], field[1]
		switch strings.ToLower(name) {
		case "host":
			if major != 1 {
				continue
			}
			value = u.Host
		case "connection":
			if major != 1 {
				continue
			}
		case "content-length":
			if body == "" {
				continue
			}
			value = strconv.Itoa(len(body))
		case "cookie":
			if major == 2 || (major == 3 && browser == "chrome" && device != "ios") {
				fields = append(fields, [2]string{"cookie", "first=1"}, [2]string{"cookie", "second=2"})
				continue
			}
		}
		if major != 1 {
			name = strings.ToLower(name)
		}
		fields = append(fields, [2]string{name, value})
		if strings.EqualFold(name, "x-multi") {
			fields = append(fields, [2]string{name, "second"})
		}
	}
	return fields
}

func profileOrderCheck(t *testing.T, c *surf.Client, origin, browser, device, method string, major int, captures <-chan profileWireCapture, pseudo []string) {
	t.Helper()
	req, path, body := profileOrderRequest(t, c, origin, method, pseudo)
	original := req.GetRequest().Header.Clone()
	response := req.Do()
	require.False(t, response.IsErr(), "%v", response.Err())
	result := response.Unwrap()
	require.Equal(t, 200, int(result.StatusCode))
	require.Equal(t, major, result.GetResponse().ProtoMajor, "verify the transport actually used on the wire")
	_, err := io.Copy(io.Discard, result.GetResponse().Body)
	require.NoError(t, err)
	require.NoError(t, result.Body.Close())
	require.Equal(t, original, req.GetRequest().Header, "wire preparation must preserve explicit logical fields and metadata")
	var capture profileWireCapture
	select {
	case capture = <-captures:
	case <-time.After(5 * time.Second):
		t.Fatal("missing complete profile wire capture")
	}
	require.Equal(t, method, capture.method)
	if method == http.MethodConnect && major == 1 {
		u, err := url.Parse(origin)
		require.NoError(t, err)
		require.Equal(t, u.Host, capture.path)
	} else {
		require.Equal(t, path, capture.path)
	}
	require.Equal(t, body, capture.body)
	require.Equal(t, profileOrderExpected(t, origin, browser, device, method, path, body, major, pseudo), capture.fields,
		"full wire field order, values, casing, repeats and metadata exclusion must follow explicit application settings")
}

func TestHeaderProfileExplicitOrderOnWire(t *testing.T) {
	// Thirty persistent peers cover 210 requests. The method dimension is
	// sequential so this matrix does not multiply CI socket/handshake load.
	for _, browser := range []string{"chrome", "firefox"} {
		for _, device := range []string{"windows", "macos", "linux", "android", "ios"} {
			for _, major := range []int{1, 2, 3} {
				t.Run(fmt.Sprintf("%s/%s/http%d", browser, device, major), func(t *testing.T) {
					origin, captures := newProfileWirePeer(t, major, nil)
					c := profileOrderClient(t, browser, device, major)
					for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
						if !t.Run(method, func(t *testing.T) {
							profileOrderCheck(t, c, origin, browser, device, method, major, captures, nil)
						}) {
							return
						}
					}
				})
			}
		}
	}
}

func TestHeaderProfileExplicitPseudoOrderOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, major := range []int{2, 3} {
			t.Run(fmt.Sprintf("%s/http%d", browser, major), func(t *testing.T) {
				origin, captures := newProfileWirePeer(t, major, nil)
				c := profileOrderClient(t, browser, "windows", major)
				profileOrderCheck(t, c, origin, browser, "windows", http.MethodGet, major, captures,
					[]string{":path", ":scheme", ":method", ":authority"})
			})
		}
	}
}

func TestHeaderProfileGenericMethodsOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, major := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/http%d", browser, major), func(t *testing.T) {
				origin, captures := newProfileWirePeer(t, major, nil)
				c := profileOrderClient(t, browser, "windows", major)
				for _, method := range []string{http.MethodTrace, http.MethodConnect} {
					t.Run(method, func(t *testing.T) {
						if major == 3 && method == http.MethodConnect {
							// CONNECT currently requires TCP even with ForceHTTP3.
							// Exercise that contract on H2, including the late layout
							// and cookie splitting selected for the actual transport.
							tcpOrigin, tcpCaptures := newProfileWirePeer(t, 2, nil)
							profileOrderCheck(t, c, tcpOrigin, browser, "windows", method, 2, tcpCaptures, nil)
							return
						}
						profileOrderCheck(t, c, origin, browser, "windows", method, major, captures, nil)
					})
				}
			})
		}
	}
}
