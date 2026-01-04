package socks4

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

type mockDialer struct {
	writeResp []byte
	readResp  []byte
	failDial  bool
}

func (m *mockDialer) Dial(network, addr string) (net.Conn, error) {
	if m.failDial {
		return nil, errors.New("dial failed")
	}

	return &mockConn{
		writeBuf: &bytes.Buffer{},
		readBuf:  bytes.NewBuffer(m.readResp),
	}, nil
}

type mockConn struct {
	writeBuf *bytes.Buffer
	readBuf  *bytes.Buffer
	closed   bool
}

func (m *mockConn) Read(p []byte) (int, error)         { return m.readBuf.Read(p) }
func (m *mockConn) Write(p []byte) (int, error)        { return m.writeBuf.Write(p) }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRequestBytes_SOCKS4(t *testing.T) {
	req := request{
		Host: "1.2.3.4",
		Port: 1080,
		IP:   net.IPv4(1, 2, 3, 4),
		Is4a: false,
	}

	b, err := req.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if b[0] != socksVersion || b[1] != socksConnect {
		t.Fatal("wrong version or command")
	}

	// check port (big endian)
	if b[2] != 0x04 || b[3] != 0x38 { // 1080 = 0x0438
		t.Fatal("wrong port encoding")
	}

	// check IP
	if !bytes.Equal(b[4:8], []byte{1, 2, 3, 4}) {
		t.Fatal("wrong IP")
	}

	// check null-terminated USERID
	if b[8] != 'n' {
		t.Fatal("missing userid")
	}
}

func TestRequestBytes_SOCKS4a(t *testing.T) {
	req := request{
		Host: "example.com",
		Port: 1080,
		IP:   net.IPv4(0, 0, 0, 1),
		Is4a: true,
	}

	b, err := req.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.HasSuffix(b, []byte("example.com\x00")) {
		t.Fatal("socks4a hostname not appended")
	}
}

func TestDial_WrongNetwork(t *testing.T) {
	u, _ := url.Parse("socks4://127.0.0.1:1080")
	d := socks4{url: u, dialer: &mockDialer{}}

	_, err := d.Dial("udp", "1.2.3.4:80")
	if err == nil {
		t.Fatal("expected error for wrong network")
	}
}

func TestDial_DialFail(t *testing.T) {
	u, _ := url.Parse("socks4://127.0.0.1:1080")
	d := socks4{url: u, dialer: &mockDialer{failDial: true}}

	_, err := d.Dial("tcp", "1.2.3.4:80")
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestDial_AccessGranted(t *testing.T) {
	u, _ := url.Parse("socks4://127.0.0.1:1080")
	mock := &mockDialer{
		readResp: []byte{0x00, accessGranted, 0, 0, 0, 0, 0, 0},
	}
	d := socks4{url: u, dialer: mock}

	c, err := d.Dial("tcp", "1.2.3.4:1080")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected connection")
	}
}

func TestDial_AccessRejected(t *testing.T) {
	u, _ := url.Parse("socks4://127.0.0.1:1080")
	mock := &mockDialer{
		readResp: []byte{0x00, accessRejected, 0, 0, 0, 0, 0, 0},
	}
	d := socks4{url: u, dialer: mock}

	_, err := d.Dial("tcp", "1.2.3.4:1080")
	if err == nil {
		t.Fatal("expected ErrConnRejected")
	}
}

func TestDial_AccessIdentRequired(t *testing.T) {
	u, _ := url.Parse("socks4://127.0.0.1:1080")
	mock := &mockDialer{
		readResp: []byte{0x00, accessIdentRequired, 0, 0, 0, 0, 0, 0},
	}
	d := socks4{url: u, dialer: mock}

	_, err := d.Dial("tcp", "1.2.3.4:1080")
	if _, ok := err.(*ErrIdentRequired); !ok {
		t.Fatal("expected ErrIdentRequired")
	}
}
