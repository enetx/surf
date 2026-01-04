package sse_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/surf/pkg/sse"
)

func TestSSEEventBasic(t *testing.T) {
	t.Parallel()

	event := &sse.Event{
		ID:    "123",
		Event: "message",
		Data:  "Hello, world!",
		Retry: 5000,
	}

	if event.ID != "123" {
		t.Errorf("expected ID to be '123', got %s", event.ID)
	}

	if event.Event != "message" {
		t.Errorf("expected Event to be 'message', got %s", event.Event)
	}

	if event.Data != "Hello, world!" {
		t.Errorf("expected Data to be 'Hello, world!', got %s", event.Data)
	}

	if event.Retry != 5000 {
		t.Errorf("expected Retry to be 5000, got %d", event.Retry)
	}
}

func TestSSEEventSkip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		data     g.String
		expected bool
	}{
		{"empty data", "", true},
		{"null data", "null", true},
		{"undefined data", "undefined", true},
		{"valid data", "Hello", false},
		{"valid json", `{"key":"value"}`, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &sse.Event{Data: tc.data}
			if event.Skip() != tc.expected {
				t.Errorf("expected Skip() to return %t for data %s", tc.expected, tc.data)
			}
		})
	}
}

func TestSSEEventDone(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		data     g.String
		expected bool
	}{
		{"done marker", "[DONE]", true},
		{"normal data", "Hello", false},
		{"empty data", "", false},
		{"similar but not done", "[DONE", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &sse.Event{Data: tc.data}
			if event.Done() != tc.expected {
				t.Errorf("expected Done() to return %t for data %s", tc.expected, tc.data)
			}
		})
	}
}

func TestSSEReadBasic(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`data: Hello World

data: Second message

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Data != "Hello World" {
		t.Errorf("expected first event data to be 'Hello World', got %s", events[0].Data)
	}

	if events[1].Data != "Second message" {
		t.Errorf("expected second event data to be 'Second message', got %s", events[1].Data)
	}
}

func TestSSEReadWithEventType(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`event: notification
data: New notification

event: update
data: System updated

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Event != "notification" {
		t.Errorf("expected first event type to be 'notification', got %s", events[0].Event)
	}

	if events[1].Event != "update" {
		t.Errorf("expected second event type to be 'update', got %s", events[1].Event)
	}
}

func TestSSEReadWithID(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`id: 123
data: Message with ID

id: 456
data: Another message

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].ID != "123" {
		t.Errorf("expected first event ID to be '123', got %s", events[0].ID)
	}

	if events[1].ID != "456" {
		t.Errorf("expected second event ID to be '456', got %s", events[1].ID)
	}
}

func TestSSEReadWithRetry(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`retry: 3000
data: Message with retry

retry: invalid
data: Message with invalid retry

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Retry != 3000 {
		t.Errorf("expected first event retry to be 3000, got %d", events[0].Retry)
	}

	if events[1].Retry != -1 {
		t.Errorf("expected second event retry to be -1 (invalid), got %d", events[1].Retry)
	}
}

func TestSSEReadStopProcessing(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`data: First message

data: Second message

data: Third message

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		// Stop after first event
		return len(events) < 1
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Data != "First message" {
		t.Errorf("expected event data to be 'First message', got %s", events[0].Data)
	}
}

func TestSSEReadComplexFormat(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`id: msg-1
event: user-message
data: {"user":"john","message":"hello"}
retry: 5000

id: msg-2
event: system-notification
data: {"type":"warning","text":"Server maintenance in 5 minutes"}

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// First event
	if events[0].ID != "msg-1" {
		t.Errorf("expected first event ID to be 'msg-1', got %s", events[0].ID)
	}
	if events[0].Event != "user-message" {
		t.Errorf("expected first event type to be 'user-message', got %s", events[0].Event)
	}
	if events[0].Retry != 5000 {
		t.Errorf("expected first event retry to be 5000, got %d", events[0].Retry)
	}

	// Second event
	if events[1].ID != "msg-2" {
		t.Errorf("expected second event ID to be 'msg-2', got %s", events[1].ID)
	}
	if events[1].Event != "system-notification" {
		t.Errorf("expected second event type to be 'system-notification', got %s", events[1].Event)
	}
}

func TestSSEReadEmptyLines(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`data: First message


data: Second message



`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		if !event.Skip() {
			events = append(events, *event)
		}
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestSSEReadInvalidFormat(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader(`invalidline
data: Valid message

`)

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		if !event.Skip() {
			events = append(events, *event)
		}
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should still process the valid message despite invalid line
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Data != "Valid message" {
		t.Errorf("expected event data to be 'Valid message', got %s", events[0].Data)
	}
}

func TestSSEReadEmptyReader(t *testing.T) {
	t.Parallel()

	sseData := strings.NewReader("")

	var events []sse.Event
	err := sse.Read(sseData, func(event *sse.Event) bool {
		events = append(events, *event)
		return true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestSSEReadErrorReader(t *testing.T) {
	t.Parallel()

	errorReader := &errorReader{err: fmt.Errorf("read error")}

	err := sse.Read(errorReader, func(*sse.Event) bool {
		return true
	})

	if err == nil {
		t.Fatal("expected error from errorReader")
	}

	if err.Error() != "read error" {
		t.Errorf("expected error message 'read error', got %s", err.Error())
	}
}

// errorReader is a helper type that always returns an error
type errorReader struct {
	err error
}

func (er *errorReader) Read([]byte) (n int, err error) {
	return 0, er.err
}

var _ io.Reader = (*errorReader)(nil)
