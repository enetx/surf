package drainbody_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/surf/internal/drainbody"
)

func TestDrainBodyNil(t *testing.T) {
	t.Parallel()

	data, r, err := drainbody.DrainBody(nil)
	if err != nil {
		t.Errorf("expected no error for nil body, got %v", err)
	}
	if data != nil {
		t.Error("expected nil data for nil body")
	}
	if r != nil {
		t.Error("expected nil reader for nil body")
	}
}

func TestDrainBodyNoBody(t *testing.T) {
	t.Parallel()

	data, r, err := drainbody.DrainBody(http.NoBody)
	if err != nil {
		t.Errorf("expected no error for NoBody, got %v", err)
	}
	if data != nil {
		t.Error("expected nil data for NoBody")
	}
	if r != nil {
		t.Error("expected nil reader for NoBody")
	}
}

func TestDrainBodyNormalOperation(t *testing.T) {
	t.Parallel()

	originalData := "test data for draining"
	body := io.NopCloser(strings.NewReader(originalData))

	data, r, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data == nil {
		t.Fatal("expected non-nil data")
	}
	if r == nil {
		t.Fatal("expected non-nil reader")
	}

	// Check bytes match
	if string(data) != originalData {
		t.Errorf("expected %q from data, got %q", originalData, string(data))
	}

	// Read from reader
	readData, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading from reader: %v", err)
	}
	if string(readData) != originalData {
		t.Errorf("expected %q from reader, got %q", originalData, string(readData))
	}

	// Close reader
	if err := r.Close(); err != nil {
		t.Errorf("error closing reader: %v", err)
	}
}

func TestDrainBodyEmptyBody(t *testing.T) {
	t.Parallel()

	body := io.NopCloser(strings.NewReader(""))

	data, r, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data == nil {
		t.Fatal("expected non-nil data (empty slice)")
	}
	if r == nil {
		t.Fatal("expected non-nil reader")
	}

	// Should be empty
	if len(data) != 0 {
		t.Errorf("expected empty data, got %q", string(data))
	}

	readData, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading from reader: %v", err)
	}
	if len(readData) != 0 {
		t.Errorf("expected empty read data, got %q", string(readData))
	}
}

func TestDrainBodyLargeData(t *testing.T) {
	t.Parallel()

	// Create large data (1MB)
	largeData := strings.Repeat("abcdefghij", 100*1024)
	body := io.NopCloser(strings.NewReader(largeData))

	data, r, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check bytes
	if string(data) != largeData {
		t.Error("data doesn't match original")
	}

	// Read from reader
	readData, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading from reader: %v", err)
	}
	if string(readData) != largeData {
		t.Error("reader data doesn't match original")
	}

	// Verify lengths
	if len(data) != len(largeData) {
		t.Errorf("expected length %d from data, got %d", len(largeData), len(data))
	}
	if len(readData) != len(largeData) {
		t.Errorf("expected length %d from reader, got %d", len(largeData), len(readData))
	}
}

// TestReadCloser implements io.ReadCloser for testing error scenarios
type TestReadCloser struct {
	reader    io.Reader
	readErr   error
	closeErr  error
	readCalls int
}

func (t *TestReadCloser) Read(p []byte) (n int, err error) {
	t.readCalls++
	if t.readErr != nil {
		return 0, t.readErr
	}
	return t.reader.Read(p)
}

func (t *TestReadCloser) Close() error {
	return t.closeErr
}

func TestDrainBodyReadError(t *testing.T) {
	t.Parallel()

	readErr := errors.New("read error")
	body := &TestReadCloser{
		reader:  strings.NewReader("test"),
		readErr: readErr,
	}

	data, r, err := drainbody.DrainBody(body)
	if err == nil {
		t.Fatal("expected error for read failure")
	}
	if err != readErr {
		t.Errorf("expected read error, got %v", err)
	}
	if data != nil {
		t.Error("expected nil data on read error")
	}
	if r != nil {
		t.Error("expected nil reader on read error")
	}
}

func TestDrainBodyCloseError(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("close error")
	body := &TestReadCloser{
		reader:   strings.NewReader("test"),
		closeErr: closeErr,
	}

	data, r, err := drainbody.DrainBody(body)
	if err == nil {
		t.Fatal("expected error for close failure")
	}
	if err != closeErr {
		t.Errorf("expected close error, got %v", err)
	}
	if data != nil {
		t.Error("expected nil data on close error")
	}
	if r != nil {
		t.Error("expected nil reader on close error")
	}
}

func TestDrainBodyBinaryData(t *testing.T) {
	t.Parallel()

	// Test with binary data including null bytes
	binaryData := []byte{0, 1, 2, 3, 255, 254, 253, 0, 127, 128}
	body := io.NopCloser(bytes.NewReader(binaryData))

	data, r, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify binary data matches
	if !bytes.Equal(data, binaryData) {
		t.Error("data binary doesn't match original")
	}

	readData, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading from reader: %v", err)
	}
	if !bytes.Equal(readData, binaryData) {
		t.Error("reader binary data doesn't match original")
	}
}

func TestDrainBodyRetrySupport(t *testing.T) {
	t.Parallel()

	originalData := "data for retry test"
	body := io.NopCloser(strings.NewReader(originalData))

	// First drain
	data, r1, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read from first reader (simulating first request)
	readData1, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("error reading from r1: %v", err)
	}
	if string(readData1) != originalData {
		t.Errorf("first read doesn't match: %q", string(readData1))
	}

	// Create new reader from saved bytes (simulating retry)
	r2 := io.NopCloser(bytes.NewReader(data))
	readData2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}
	if string(readData2) != originalData {
		t.Errorf("retry read doesn't match: %q", string(readData2))
	}

	// Can create multiple readers from same bytes
	r3 := io.NopCloser(bytes.NewReader(data))
	readData3, err := io.ReadAll(r3)
	if err != nil {
		t.Fatalf("error reading from r3: %v", err)
	}
	if string(readData3) != originalData {
		t.Errorf("third read doesn't match: %q", string(readData3))
	}
}
