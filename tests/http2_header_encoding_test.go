package surf_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"reflect"
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

func TestHTTP2HeaderEncodingFluentOnWire(t *testing.T) {
	type capture struct {
		fields   []hpack.HeaderField
		priority http2.PriorityParam
	}
	got := make(chan capture, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("fell back to HTTP/1") }))
	server.EnableHTTP2 = true
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
		if err := fr.WriteSettings(); err != nil {
			return
		}
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					fr.WriteSettingsAck()
				}
			case *http2.MetaHeadersFrame:
				got <- capture{f.Fields, f.Priority}
				var block bytes.Buffer
				hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, EndHeaders: true, EndStream: true, BlockFragment: block.Bytes()})
				return
			}
		}
	}}
	server.StartTLS()
	defer server.Close()
	builder := surf.NewClient().Builder().ForceHTTP2()
	settings := builder.HTTP2Settings().HpackDefaultRepresentation(surf.HPACKWithoutIndexing).
		HpackPolicy(func(name, value string) surf.HPACKRepresentation {
			if name == "x-policy" {
				return surf.HPACKNeverIndex
			}
			return surf.HPACKWithoutIndexing
		}).
		HpackRepresentation("Authorization", surf.HPACKNeverIndex).
		HeaderPriority(func(req http2.PriorityRequest) http2.PriorityParam {
			require.Equal(t, "/wire", req.URL.Path)
			return http2.PriorityParam{Exclusive: true, Weight: 123}
		}).ChainStreamDependencies(true)
	client := settings.Set().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	settings.HpackRepresentation("authorization", surf.HPACKDefault).HeaderPriority(nil)
	response := client.Get(g.String(server.URL+"/wire")).SetHeaders("authorization", "secret").SetHeaders("x-policy", "value").Do()
	require.False(t, response.IsErr(), "%v", response.Err())
	response.Ok().Body.Close()
	select {
	case capture := <-got:
		require.True(t, reflect.DeepEqual(http2.PriorityParam{Exclusive: true, Weight: 123}, capture.priority))
		seen := map[string]bool{}
		for _, f := range capture.fields {
			if f.Name == "authorization" || f.Name == "x-policy" {
				require.True(t, f.Sensitive)
				seen[f.Name] = true
			}
		}
		require.Len(t, seen, 2)
	case <-time.After(time.Second):
		t.Fatal("missing HTTP/2 headers")
	}
}

func TestHTTP2HeaderEncodingBuildValidation(t *testing.T) {
	for _, configure := range []func(*surf.HTTP2Settings){
		func(h *surf.HTTP2Settings) { h.HpackHuffman(99) },
		func(h *surf.HTTP2Settings) { h.HpackNameReferencePolicy(99) },
		func(h *surf.HTTP2Settings) { h.HpackDefaultRepresentation(99) },
		func(h *surf.HTTP2Settings) { h.HpackRepresentation("bad name", surf.HPACKNeverIndex) },
		func(h *surf.HTTP2Settings) { h.HpackRepresentation("x", 99) },
	} {
		h := surf.NewClient().Builder().HTTP2Settings()
		configure(h)
		result := h.Set().Build()
		require.True(t, result.IsErr())
		require.ErrorContains(t, result.Err(), "HPACK")
	}
}
