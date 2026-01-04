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

	r1, r2, err := drainbody.DrainBody(nil)
	if err != nil {
		t.Errorf("expected no error for nil body, got %v", err)
	}
	if r1 != nil {
		t.Error("expected nil r1 for nil body")
	}
	if r2 != nil {
		t.Error("expected nil r2 for nil body")
	}
}

func TestDrainBodyNoBody(t *testing.T) {
	t.Parallel()

	r1, r2, err := drainbody.DrainBody(http.NoBody)
	if err != nil {
		t.Errorf("expected no error for NoBody, got %v", err)
	}
	if r1 != nil {
		t.Error("expected nil r1 for NoBody")
	}
	if r2 != nil {
		t.Error("expected nil r2 for NoBody")
	}
}

func TestDrainBodyNormalOperation(t *testing.T) {
	t.Parallel()

	originalData := "test data for draining"
	body := io.NopCloser(strings.NewReader(originalData))

	r1, r2, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if r1 == nil {
		t.Fatal("expected non-nil r1")
	}
	if r2 == nil {
		t.Fatal("expected non-nil r2")
	}

	// Read from first reader
	data1, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("error reading from r1: %v", err)
	}
	if string(data1) != originalData {
		t.Errorf("expected %q from r1, got %q", originalData, string(data1))
	}

	// Read from second reader
	data2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}
	if string(data2) != originalData {
		t.Errorf("expected %q from r2, got %q", originalData, string(data2))
	}

	// Close both readers
	if err := r1.Close(); err != nil {
		t.Errorf("error closing r1: %v", err)
	}
	if err := r2.Close(); err != nil {
		t.Errorf("error closing r2: %v", err)
	}
}

func TestDrainBodyEmptyBody(t *testing.T) {
	t.Parallel()

	body := io.NopCloser(strings.NewReader(""))

	r1, r2, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if r1 == nil {
		t.Fatal("expected non-nil r1")
	}
	if r2 == nil {
		t.Fatal("expected non-nil r2")
	}

	// Read from both readers - should be empty
	data1, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("error reading from r1: %v", err)
	}
	if len(data1) != 0 {
		t.Errorf("expected empty data from r1, got %q", string(data1))
	}

	data2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}
	if len(data2) != 0 {
		t.Errorf("expected empty data from r2, got %q", string(data2))
	}
}

func TestDrainBodyLargeData(t *testing.T) {
	t.Parallel()

	// Create large data (1MB)
	largeData := strings.Repeat("abcdefghij", 100*1024)
	body := io.NopCloser(strings.NewReader(largeData))

	r1, r2, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read from first reader
	data1, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("error reading from r1: %v", err)
	}
	if string(data1) != largeData {
		t.Error("r1 data doesn't match original")
	}

	// Read from second reader
	data2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}
	if string(data2) != largeData {
		t.Error("r2 data doesn't match original")
	}

	// Verify lengths
	if len(data1) != len(largeData) {
		t.Errorf("expected length %d from r1, got %d", len(largeData), len(data1))
	}
	if len(data2) != len(largeData) {
		t.Errorf("expected length %d from r2, got %d", len(largeData), len(data2))
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

	r1, r2, err := drainbody.DrainBody(body)
	if err == nil {
		t.Fatal("expected error for read failure")
	}
	if err != readErr {
		t.Errorf("expected read error, got %v", err)
	}
	if r1 != nil {
		t.Error("expected nil r1 on read error")
	}
	if r2 != nil {
		t.Error("expected nil r2 on read error")
	}
}

func TestDrainBodyCloseError(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("close error")
	body := &TestReadCloser{
		reader:   strings.NewReader("test"),
		closeErr: closeErr,
	}

	r1, r2, err := drainbody.DrainBody(body)
	if err == nil {
		t.Fatal("expected error for close failure")
	}
	if err != closeErr {
		t.Errorf("expected close error, got %v", err)
	}
	if r1 != nil {
		t.Error("expected nil r1 on close error")
	}
	if r2 != nil {
		t.Error("expected nil r2 on close error")
	}
}

func TestDrainBodyBinaryData(t *testing.T) {
	t.Parallel()

	// Test with binary data including null bytes
	binaryData := []byte{0, 1, 2, 3, 255, 254, 253, 0, 127, 128}
	body := io.NopCloser(bytes.NewReader(binaryData))

	r1, r2, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read from both readers
	data1, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("error reading from r1: %v", err)
	}

	data2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}

	// Verify binary data matches
	if !bytes.Equal(data1, binaryData) {
		t.Error("r1 binary data doesn't match original")
	}
	if !bytes.Equal(data2, binaryData) {
		t.Error("r2 binary data doesn't match original")
	}
}

func TestDrainBodyMultipleReads(t *testing.T) {
	t.Parallel()

	originalData := "test data for multiple reads"
	body := io.NopCloser(strings.NewReader(originalData))

	r1, r2, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read from r1 in chunks
	var buf1 bytes.Buffer
	chunk := make([]byte, 5)
	for {
		n, err := r1.Read(chunk)
		if n > 0 {
			buf1.Write(chunk[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("error reading chunk from r1: %v", err)
		}
	}

	// Read from r2 all at once
	data2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}

	// Verify both match original
	if buf1.String() != originalData {
		t.Errorf("expected %q from r1 chunks, got %q", originalData, buf1.String())
	}
	if string(data2) != originalData {
		t.Errorf("expected %q from r2, got %q", originalData, string(data2))
	}
}

func TestDrainBodyReadersAreIndependent(t *testing.T) {
	t.Parallel()

	originalData := "independent readers test"
	body := io.NopCloser(strings.NewReader(originalData))

	r1, r2, err := drainbody.DrainBody(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read partial from r1
	partial := make([]byte, 5)
	n1, err := r1.Read(partial)
	if err != nil && err != io.EOF {
		t.Fatalf("error reading partial from r1: %v", err)
	}

	// Read full from r2 - should not be affected by r1's partial read
	data2, err := io.ReadAll(r2)
	if err != nil {
		t.Fatalf("error reading from r2: %v", err)
	}
	if string(data2) != originalData {
		t.Errorf("r2 should have full data despite r1 partial read, got %q", string(data2))
	}

	// Continue reading r1
	remaining, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("error reading remaining from r1: %v", err)
	}

	fullR1 := string(partial[:n1]) + string(remaining)
	if fullR1 != originalData {
		t.Errorf("r1 full read doesn't match original: %q", fullR1)
	}
}
