package main

import (
	"github.com/enetx/quic-go/http3/qlog"
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
	frame, ok := event.(qlog.FrameParsed)
	if !ok {
		return
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
