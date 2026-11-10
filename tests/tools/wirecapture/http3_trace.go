package main

import (
	"encoding/json"
	"time"

	"github.com/enetx/quic-go/http3/qlog"
	transportqlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
)

// Preserve received field order for exact-input replay. The independent
// Wireshark decode of wire.pcap is checked against these decoded fields.
type headerTrace struct {
	server            *captureServer
	label, connection string
}

func (t *headerTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *headerTrace) Close() error                     { return nil }
func (t *headerTrace) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case transportqlog.PacketSent:
		t.recordPacket("sent", e.Header, e.Frames)
	case transportqlog.PacketReceived:
		t.recordPacket("received", e.Header, e.Frames)
	}
	frame, ok := event.(qlog.FrameParsed)
	if !ok {
		return
	}
	if t.server.frameRecords != nil {
		record := map[string]any{"label": t.label, "connection": t.connection, "stream_id": uint64(frame.StreamID)}
		switch f := frame.Frame.Frame.(type) {
		case qlog.DataFrame:
			record["type"] = "DATA"
			record["length"] = frame.Raw.PayloadLength
		case qlog.PriorityUpdateFrame:
			record["type"] = "PRIORITY_UPDATE"
			record["request_stream_id"] = uint64(f.StreamID)
			record["priority"] = f.PriorityFieldValue
		default:
			record = nil
		}
		if record != nil {
			t.server.mu.Lock()
			if err := json.NewEncoder(t.server.frameRecords).Encode(record); err != nil {
				t.server.errors = append(t.server.errors, err.Error())
			}
			t.server.mu.Unlock()
		}
	}
	headers, ok := frame.Frame.Frame.(qlog.HeadersFrame)
	if !ok {
		return
	}
	req := observedRequest{Label: t.label, Connection: t.connection, Protocol: "h3", StreamID: uint64(frame.StreamID)}
	for _, field := range headers.HeaderFields {
		req.Fields = append(req.Fields, headerField{field.Name, field.Value})
		if field.Name == ":path" {
			req.Path = field.Value
		}
		if field.Name == ":method" {
			req.Method = field.Value
		}
	}
	if req.Path != "" {
		t.server.record(req)
	}
}

// Server-side decrypted frame observations from actual peer packets. Packet
// timings include tracing overhead; they do not establish NIC pacing parity.
func (t *headerTrace) recordPacket(direction string, header transportqlog.PacketHeader, frames []transportqlog.Frame) {
	if header.PacketType != transportqlog.PacketType1RTT || t.server.packetRecords == nil {
		return
	}
	var ranges [][2]uint64
	var delay time.Duration
	eliciting := false
	for _, f := range frames {
		if ack, ok := f.Frame.(*transportqlog.AckFrame); ok {
			for _, r := range ack.AckRanges {
				ranges = append(ranges, [2]uint64{uint64(r.Smallest), uint64(r.Largest)})
			}
			delay = ack.DelayTime
		} else {
			eliciting = true
		}
	}
	t.server.mu.Lock()
	defer t.server.mu.Unlock()
	err := json.NewEncoder(t.server.packetRecords).Encode(map[string]any{"label": t.label, "connection": t.connection, "direction": direction, "packet_number": uint64(header.PacketNumber), "eliciting": eliciting, "ack_ranges": ranges, "ack_delay_ns": int64(delay)})
	if err != nil {
		t.server.errors = append(t.server.errors, err.Error())
	}
}
