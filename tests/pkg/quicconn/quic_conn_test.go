package quicconn_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enetx/surf/pkg/quicconn"
)

// mockConn is a mock implementation of net.Conn for testing.
type mockConn struct {
	readData   []byte
	readPos    int
	writeData  bytes.Buffer
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
	readErr    error
	writeErr   error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeData.Write(b)
}

func (m *mockConn) Close() error { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (m *mockConn) SetDeadline(time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(time.Time) error { return nil }

// mockShortWriteConn simulates short writes (n < len(buf) without error).
type mockShortWriteConn struct {
	mockConn
	writeCount int
}

func (m *mockShortWriteConn) Write(b []byte) (int, error) {
	m.writeCount++
	if m.writeCount == 1 {
		// short write by 1 byte, no error
		return len(b) - 1, nil
	}
	return m.mockConn.Write(b)
}

// buildSOCKS5UDPHeader builds RFC1928 UDP header for IPv4/IPv6 (no DOMAIN in tests).
func buildSOCKS5UDPHeader(ip net.IP, port int) []byte {
	h := make([]byte, 0, 4+16+2)
	h = append(h, 0x00, 0x00, 0x00) // RSV, RSV, FRAG=0
	if ip4 := ip.To4(); ip4 != nil {
		h = append(h, 0x01) // IPv4
		h = append(h, ip4...)
	} else {
		h = append(h, 0x04) // IPv6
		h = append(h, ip.To16()...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	h = append(h, p...)
	return h
}

// buildSOCKS5UDPHeaderFrag builds header with non-zero FRAG to trigger error.
func buildSOCKS5UDPHeaderFrag(ip net.IP, port int, frag byte) []byte {
	h := make([]byte, 0, 4+16+2)
	h = append(h, 0x00, 0x00, frag)
	if ip4 := ip.To4(); ip4 != nil {
		h = append(h, 0x01)
		h = append(h, ip4...)
	} else {
		h = append(h, 0x04)
		h = append(h, ip.To16()...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	h = append(h, p...)
	return h
}

// --- Tests ---

func TestNew_EncapRaw_PanicsOnNilDefaultTarget(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when defaultTarget is nil in EncapRaw mode")
		}
	}()
	pc := quicconn.New(&mockConn{}, nil, quicconn.EncapRaw)
	_ = pc
}

func TestNew_EncapRaw_ImplementsPacketConn(t *testing.T) {
	t.Parallel()
	pc := quicconn.New(&mockConn{}, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}, quicconn.EncapRaw)
	var _ net.PacketConn = pc
}

func TestReadFrom_Raw_Success(t *testing.T) {
	t.Parallel()
	data := []byte("test data")
	mc := &mockConn{readData: data}
	dst := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}
	pc := quicconn.New(mc, dst, quicconn.EncapRaw)

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != len(data) || !bytes.Equal(buf[:n], data) {
		t.Fatalf("unexpected payload: n=%d data=%q", n, buf[:n])
	}
	if addr.String() != dst.String() {
		t.Fatalf("unexpected addr: got %s want %s", addr, dst)
	}
}

func TestReadFrom_Raw_BufferTooSmall(t *testing.T) {
	t.Parallel()
	data := []byte("abcdef")
	mc := &mockConn{readData: data}
	dst := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1}
	pc := quicconn.New(mc, dst, quicconn.EncapRaw)

	buf := make([]byte, 3)
	_, _, err := pc.ReadFrom(buf)
	if err == nil || err.Error() != "buffer too small" {
		t.Fatalf("expected buffer too small, got %v", err)
	}
}

func TestWriteTo_Raw_Success(t *testing.T) {
	t.Parallel()
	mc := &mockConn{}
	dst := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	pc := quicconn.New(mc, dst, quicconn.EncapRaw)

	payload := []byte("ping")
	n, err := pc.WriteTo(payload, dst)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("short write count: got %d want %d", n, len(payload))
	}
	if !bytes.Equal(mc.writeData.Bytes(), payload) {
		t.Fatalf("written mismatch: got %q want %q", mc.writeData.Bytes(), payload)
	}
}

func TestWriteTo_Raw_ShortWrite(t *testing.T) {
	t.Parallel()
	mc := &mockShortWriteConn{}
	dst := &net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53}
	pc := quicconn.New(mc, dst, quicconn.EncapRaw)

	_, err := pc.WriteTo([]byte("abcd"), dst)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v", err)
	}
}

func TestReadFrom_Socks5_WithHeader_Success(t *testing.T) {
	t.Parallel()
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 4444}
	payload := []byte("hello")
	header := buildSOCKS5UDPHeader(src.IP, src.Port)
	packet := append(header, payload...)

	mc := &mockConn{readData: packet}
	// defaultTarget can be nil in EncapSocks5 if header present
	pc := quicconn.New(mc, nil, quicconn.EncapSocks5)

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != len(payload) || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
	if addr.String() != src.String() {
		t.Fatalf("unexpected addr: got %s want %s", addr, src)
	}
}

func TestReadFrom_Socks5_WithFragError(t *testing.T) {
	t.Parallel()
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000}
	header := buildSOCKS5UDPHeaderFrag(src.IP, src.Port, 0x01) // FRAG=1
	packet := append(header, []byte("x")...)

	mc := &mockConn{readData: packet}
	pc := quicconn.New(mc, nil, quicconn.EncapSocks5)

	buf := make([]byte, 64)
	_, _, err := pc.ReadFrom(buf)
	if err == nil || err.Error() != "SOCKS5 UDP fragmentation not supported (FRAG != 0)" {
		t.Fatalf("expected FRAG error, got %v", err)
	}
}

func TestReadFrom_Socks5_NoHeader_FallbackToDefaultTarget(t *testing.T) {
	t.Parallel()
	data := []byte("raw-through-socks")
	mc := &mockConn{readData: data}
	def := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5555}
	pc := quicconn.New(mc, def, quicconn.EncapSocks5)

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != len(data) || !bytes.Equal(buf[:n], data) {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
	if addr.String() != def.String() {
		t.Fatalf("unexpected addr: got %s want %s", addr, def)
	}
}

func TestReadFrom_Socks5_NoHeader_AndNilDefaultTarget_Error(t *testing.T) {
	t.Parallel()
	mc := &mockConn{readData: []byte("raw")}
	pc := quicconn.New(mc, nil, quicconn.EncapSocks5)

	buf := make([]byte, 64)
	_, _, err := pc.ReadFrom(buf)
	if !errors.Is(err, quicconn.ErrDefaultTargetRequired) {
		t.Fatalf("expected ErrDefaultTargetRequired, got %v", err)
	}
}

func TestWriteTo_Socks5_WrapsHeader(t *testing.T) {
	t.Parallel()
	dst := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 9999}
	mc := &mockConn{}
	pc := quicconn.New(mc, dst, quicconn.EncapSocks5)

	payload := []byte("DATA")
	n, err := pc.WriteTo(payload, nil) // will use defaultTarget
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected n=%d", n)
	}

	// Verify header+payload
	wantHdr := buildSOCKS5UDPHeader(dst.IP, dst.Port)
	got := mc.writeData.Bytes()
	if len(got) < len(wantHdr) {
		t.Fatalf("written too short: %d", len(got))
	}
	if !bytes.Equal(got[:len(wantHdr)], wantHdr) || !bytes.Equal(got[len(wantHdr):], payload) {
		t.Fatalf("SOCKS5 frame mismatch: got %x, want %x + %q", got, wantHdr, payload)
	}
}

func TestWriteTo_NonUDPAddr_Error(t *testing.T) {
	t.Parallel()
	mc := &mockConn{}
	def := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1}
	pc := quicconn.New(mc, def, quicconn.EncapRaw)

	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	_, err := pc.WriteTo([]byte("test"), tcpAddr)
	if err == nil {
		t.Fatalf("expected error on non-UDP addr")
	}
}

func TestClose_And_LocalAddr_And_Deadlines(t *testing.T) {
	t.Parallel()
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
	mc := &mockConn{localAddr: local}
	def := &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2222}
	pc := quicconn.New(mc, def, quicconn.EncapRaw)

	if got := pc.LocalAddr(); got.String() != local.String() {
		t.Fatalf("LocalAddr mismatch: got %s want %s", got, local)
	}
	now := time.Now()
	if err := pc.SetDeadline(now); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := pc.SetReadDeadline(now); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := pc.SetWriteDeadline(now); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !mc.closed {
		t.Fatalf("underlying conn not closed")
	}
}

func TestConcurrent_ReadsAndWrites(t *testing.T) {
	t.Parallel()
	// Enough data for several reads (though after first, mock will hit EOF).
	mc := &mockConn{readData: bytes.Repeat([]byte("test"), 16)}
	def := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1), Port: 4443}
	pc := quicconn.New(mc, def, quicconn.EncapRaw)

	done := make(chan struct{}, 2)
	go func() {
		for range 10 {
			buf := make([]byte, 4)
			_, _, _ = pc.ReadFrom(buf)
		}
		done <- struct{}{}
	}()
	go func() {
		for range 10 {
			_, _ = pc.WriteTo([]byte("data"), def)
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// This test just exercises path with a real *net.UDPConn. The write can fail if
// the destination is unroutable, which is fine — the goal is "no panic".
func TestWithRealUDPConn_Smoke(t *testing.T) {
	t.Parallel()
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Skipf("cannot create UDP conn: %v", err)
	}
	defer udpConn.Close()

	def := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}
	pc := quicconn.New(udpConn, def, quicconn.EncapRaw)

	_, _ = pc.WriteTo([]byte("ping"), def) // may error; just ensure no panic
}

func TestReadError_And_WriteError(t *testing.T) {
	t.Parallel()
	rdErr := errors.New("read error")
	wrErr := errors.New("write error")

	// Read error
	mc1 := &mockConn{readErr: rdErr}
	def := &net.UDPAddr{IP: net.IPv4(7, 7, 7, 7), Port: 77}
	pc1 := quicconn.New(mc1, def, quicconn.EncapRaw)
	_, _, err := pc1.ReadFrom(make([]byte, 16))
	if err != rdErr {
		t.Fatalf("expected %v, got %v", rdErr, err)
	}

	// Write error
	mc2 := &mockConn{writeErr: wrErr}
	pc2 := quicconn.New(mc2, def, quicconn.EncapRaw)
	_, err = pc2.WriteTo([]byte("x"), def)
	if err != wrErr {
		t.Fatalf("expected %v, got %v", wrErr, err)
	}
}

// Test SetReadBuffer and SetWriteBuffer methods
func TestSetReadBufferAndSetWriteBuffer(t *testing.T) {
	t.Parallel()

	// Create a mock UDP connection for testing
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to create UDP listener: %v", err)
	}
	defer udpConn.Close()

	// Create a QuicPacketConn
	def := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	pc := quicconn.New(udpConn, def, quicconn.EncapRaw)

	// Test SetReadBuffer with valid value
	err = pc.SetReadBuffer(1024)
	if err != nil {
		t.Errorf("SetReadBuffer failed: %v", err)
	}

	// Test SetWriteBuffer with valid value
	err = pc.SetWriteBuffer(2048)
	if err != nil {
		t.Errorf("SetWriteBuffer failed: %v", err)
	}

	// Test SetReadBuffer with positive value (should not panic)
	err = pc.SetReadBuffer(4096)
	if err != nil {
		t.Errorf("SetReadBuffer with positive value failed: %v", err)
	}

	// Test SetWriteBuffer with positive value (should not panic)
	err = pc.SetWriteBuffer(8192)
	if err != nil {
		t.Errorf("SetWriteBuffer with positive value failed: %v", err)
	}
}

func TestSetReadBufferAndSetWriteBufferWithUnsupportedConn(t *testing.T) {
	t.Parallel()

	// Create a mock connection that doesn't support buffer operations
	mc := &mockConn{
		readData:  make([]byte, 1024),
		writeData: bytes.Buffer{},
	}

	// Create a QuicPacketConn with mock connection
	def := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	pc := quicconn.New(mc, def, quicconn.EncapRaw)

	// These operations should not panic even if buffer methods aren't supported
	err := pc.SetReadBuffer(1024)
	if err != nil {
		t.Errorf("SetReadBuffer with unsupported connection should not fail: %v", err)
	}

	err = pc.SetWriteBuffer(2048)
	if err != nil {
		t.Errorf("SetWriteBuffer with unsupported connection should not fail: %v", err)
	}
}
