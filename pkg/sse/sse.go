package sse

import (
	"bufio"
	"io"

	"github.com/enetx/g"
)

// Event represents a Server-Sent Event.
type Event struct {
	ID    g.String // ID uniquely identifies the event.
	Event g.String // Event specifies the type of the event.
	Data  g.String // Data holds the raw JSON data associated with the event as a string.
	Retry g.Int    // Retry indicates the number of retry attempts for the event.
}

// reset resets the event fields to their zero values or initial states.
func (e *Event) reset() {
	e.ID = ""
	e.Event = ""
	e.Data = ""
	e.Retry = 0
}

// parse parses the event data based on the event type.
func (e *Event) parse(t, data g.String) {
	data = data.Trim()

	switch t.Trim() {
	case "event":
		e.Event = data
	case "id":
		e.ID = data
	case "retry":
		e.Retry = data.TryInt().UnwrapOr(-1)
	case "data":
		if e.Data.IsEmpty() {
			e.Data = data
		} else {
			e.Data = e.Data + "\n" + data
		}
	}
}

// Skip checks if the event should be skipped.
func (e *Event) Skip() bool {
	if e.Data.IsEmpty() {
		return true
	}

	return g.SliceOf[g.String]("", "null", "undefined").
		Iter().
		Any(func(s g.String) bool { return e.Data.Eq(s) })
}

// Done checks if the event processing is done.
func (e *Event) Done() bool { return e.Data.Eq("[DONE]") }

// Read reads Server-Sent Events (SSE) from the provided reader and calls the provided function for each event.
func Read(reader io.Reader, fn func(event *Event) bool) error {
	var event Event

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := g.String(scanner.Text())

		delimiter := line.Index(":")
		if delimiter == -1 {
			if event != (Event{}) {
				if !fn(&event) {
					return nil
				}

				event.reset()
			}

			continue
		}

		t, data := line[:delimiter], line[delimiter+1:]
		event.parse(t, data)
	}

	return scanner.Err()
}
