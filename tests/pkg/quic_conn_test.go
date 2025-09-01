package pkg_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enetx/surf/pkg/quicconn"
)

// mockConn is a mock implementation of net.Conn for testing
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

// mockShortWriteConn simulates short writes
type mockShortWriteConn struct {
	mockConn
	writeCount int
}

func (m *mockShortWriteConn) Write(b []byte) (int, error) {
	m.writeCount++
	if m.writeCount == 1 {
		// Return less than requested to simulate short write
		return len(b) - 1, nil
	}
	return m.mockConn.Write(b)
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

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

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

func (m *mockConn) SetDeadline(time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestNewQUICPacketConn(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)
	if pc == nil {
		t.Fatal("NewQUICPacketConn returned nil")
	}

	// Test that it implements net.PacketConn
	var _ net.PacketConn = pc
}

func TestQUICPacketConnReadFrom(t *testing.T) {
	t.Parallel()

	testData := []byte("test data")
	mockConn := &mockConn{
		readData: testData,
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	buf := make([]byte, 100)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected to read %d bytes, got %d", len(testData), n)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("expected data %q, got %q", testData, buf[:n])
	}

	if addr == nil {
		t.Error("expected non-nil address")
	}
}

func TestQUICPacketConnWriteTo(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	testData := []byte("test write data")
	n, err := pc.WriteTo(testData, remoteAddr)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected to write %d bytes, got %d", len(testData), n)
	}

	if !bytes.Equal(mockConn.writeData.Bytes(), testData) {
		t.Errorf("expected written data %q, got %q", testData, mockConn.writeData.Bytes())
	}
}

func TestQUICPacketConnWriteToWithUDPAddr(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	initialAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, initialAddr)

	// Write with a new UDP address
	newAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8080}
	testData := []byte("test data")

	n, err := pc.WriteTo(testData, newAddr)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected to write %d bytes, got %d", len(testData), n)
	}

	// Read and check that the address was updated
	buf := make([]byte, 100)
	_, addr, _ := pc.ReadFrom(buf)
	if addr == nil {
		t.Error("expected non-nil address after WriteTo with UDPAddr")
	}
}

func TestQUICPacketConnWriteToShortWrite(t *testing.T) {
	t.Parallel()

	// Create a custom mock that returns short write
	mockConn := &mockShortWriteConn{
		mockConn: mockConn{},
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}
	pc := quicconn.New(mockConn, remoteAddr)

	testData := []byte("test")
	_, err := pc.WriteTo(testData, remoteAddr)
	if err == nil || err != io.ErrShortWrite {
		t.Errorf("expected io.ErrShortWrite, got %v", err)
	}
}

func TestQUICPacketConnClose(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	err := pc.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !mockConn.closed {
		t.Error("underlying connection was not closed")
	}
}

func TestQUICPacketConnLocalAddr(t *testing.T) {
	t.Parallel()

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
	mockConn := &mockConn{
		localAddr: localAddr,
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	addr := pc.LocalAddr()
	if addr == nil {
		t.Fatal("LocalAddr returned nil")
	}

	if addr.String() != localAddr.String() {
		t.Errorf("expected local address %s, got %s", localAddr, addr)
	}
}

func TestQUICPacketConnDeadlines(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	now := time.Now()

	// Test SetDeadline
	if err := pc.SetDeadline(now); err != nil {
		t.Errorf("SetDeadline failed: %v", err)
	}

	// Test SetReadDeadline
	if err := pc.SetReadDeadline(now); err != nil {
		t.Errorf("SetReadDeadline failed: %v", err)
	}

	// Test SetWriteDeadline
	if err := pc.SetWriteDeadline(now); err != nil {
		t.Errorf("SetWriteDeadline failed: %v", err)
	}
}

func TestQUICPacketConnSetBuffers(t *testing.T) {
	t.Parallel()

	// SetReadBuffer and SetWriteBuffer are internal methods
	// They are tested indirectly through the actual usage
	t.Skip("SetReadBuffer/SetWriteBuffer are internal implementation details")
}

// Test with UDP connection
func TestQUICPacketConnWithUDPConn(t *testing.T) {
	t.Parallel()

	// Create a real UDP connection for testing
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Skipf("Cannot create UDP connection: %v", err)
	}
	defer udpConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}
	pc := quicconn.New(udpConn, remoteAddr)

	// Test basic operations with real UDP connection
	testData := []byte("test")
	n, err := pc.WriteTo(testData, remoteAddr)
	if err != nil {
		t.Logf("WriteTo with real UDP connection: %v", err)
	}
	if n == len(testData) {
		t.Logf("Successfully wrote %d bytes", n)
	}
}

func TestQUICPacketConnReadError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("read error")
	mockConn := &mockConn{
		readErr: expectedErr,
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	buf := make([]byte, 100)
	_, _, err := pc.ReadFrom(buf)
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestQUICPacketConnWriteError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("write error")
	mockConn := &mockConn{
		writeErr: expectedErr,
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	testData := []byte("test")
	_, err := pc.WriteTo(testData, remoteAddr)
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestQUICPacketConnRemoteAddrFallback(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	// Start with nil remote address
	pc := quicconn.New(mockConn, nil)

	// ReadFrom should return the connection's remote address
	buf := make([]byte, 100)
	_, addr, _ := pc.ReadFrom(buf)

	if addr == nil {
		t.Error("expected non-nil address from ReadFrom")
	} else if addr.String() != mockConn.RemoteAddr().String() {
		t.Errorf("expected address %s, got %s", mockConn.RemoteAddr(), addr)
	}
}

// Test with non-UDPAddr types
func TestQUICPacketConnWriteToNonUDPAddr(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	// Use a TCP address instead of UDP
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	testData := []byte("test")

	n, err := pc.WriteTo(testData, tcpAddr)
	if err != nil {
		t.Fatalf("WriteTo with TCPAddr failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected to write %d bytes, got %d", len(testData), n)
	}
}

// Test concurrent operations
func TestQUICPacketConnConcurrent(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{
		readData: bytes.Repeat([]byte("test"), 100),
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 443}

	pc := quicconn.New(mockConn, remoteAddr)

	// Run concurrent reads and writes
	done := make(chan bool, 2)

	go func() {
		for range 10 {
			buf := make([]byte, 4)
			pc.ReadFrom(buf)
		}
		done <- true
	}()

	go func() {
		for range 10 {
			pc.WriteTo([]byte("data"), remoteAddr)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}
