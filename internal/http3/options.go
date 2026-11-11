// Package h3transport owns HTTP/3 execution and authenticated alternative routing.
package h3transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf/internal/quictls"
	"github.com/enetx/surf/profiles"
	utls "github.com/enetx/utls"
)

// HTTP/3 SETTINGS frame parameter identifiers as defined in RFC 9114.
const (
	SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
	SETTINGS_MAX_FIELD_SECTION_SIZE   = 0x06
	SETTINGS_QPACK_BLOCKED_STREAMS    = 0x07
	SETTINGS_ENABLE_CONNECT_PROTOCOL  = 0x08
	SETTINGS_H3_DATAGRAM              = 0x33
	H3_DATAGRAM                       = 0xFFD277
	SETTINGS_ENABLE_WEBTRANSPORT      = 0x2B603742
)

// Options contains construction state; public fluent builders remain in surf.
type Options struct {
	CachedRTTParameter                   uint64
	MinimumInitialRTT, MaximumInitialRTT time.Duration
	UseResolvedTCPAddresses              bool
	HTTPSRecordsWait                     func(time.Duration) time.Duration
	Discovery                            bool
	ExpireFailedAlternatives             bool
	HTTPSRecordsLookup                   HTTPSRecordsLookup
	AlternativeServiceBackoff            AlternativeServiceBackoff
	AddressFallbackDelay                 time.Duration
	ConnectionRacing                     bool
	ConnectionRacingPolicy               profiles.ConnectionRacingPolicy
	TCPFallbackDelay                     *time.Duration
	AltUsed                              bool
	EarlyData                            bool
	EarlyDataBackup                      bool
	ResumeVersion                        bool
	ClientHandshake                      *quic.ClientHandshake
	ClientHelloFactory                   func() (utls.ClientHelloSpec, error)
	ECHClientHelloInner                  utls.ECHClientHelloInnerFunc

	Settings               g.MapOrd[uint64, uint64]
	QUICConfig             *quic.Config
	QPACKConfig            *http3.QPACKConfig
	WireConfig             *http3.WireConfig
	ConnectionIDLength     *int
	ConnectionIDGenerator  quic.ConnectionIDGenerator
	StreamPriority         *http3.StreamPriority
	MaxResponseHeaderBytes int
	Datagrams              *bool

	ForceHTTP3         bool
	TCPVersion         int
	Proxy              string
	DisableCompression bool
	ProtocolHeaders    func(*http.Request, int)
	Fallback           http.RoundTripper
	RequestProxy       func(*http.Request) (*url.URL, error)
	TLSConfig          *tls.Config
	Dialer             *net.Dialer
}

const (
	DefaultMaxResponseHeaderBytes = 10 << 20
)

func (h *Options) validateQUICConfig() error {
	if h.CachedRTTParameter != 0 {
		if h.MinimumInitialRTT <= 0 || h.MaximumInitialRTT < h.MinimumInitialRTT || h.MaximumInitialRTT > (1<<63-1)/16 {
			return errors.New("cached initial RTT requires positive, ordered timeout bounds")
		}

		if err := (&transportparams.Layout{DisableGrease: true, Additional: []transportparams.Parameter{{ID: h.CachedRTTParameter}}}).Validate(); err != nil {
			return err
		}
	}

	if h.TCPFallbackDelay != nil && *h.TCPFallbackDelay < 0 {
		return fmt.Errorf("TCP fallback delay must be nonnegative")
	}

	if err := h.WireConfig.Validate(); err != nil {
		return err
	}

	if err := h.QPACKConfig.Validate(); err != nil {
		return err
	}

	handshake := h.ClientHandshake
	if handshake == nil && h.QUICConfig != nil {
		handshake = h.QUICConfig.ClientHandshake
	}

	if handshake != nil {
		if err := handshake.Validate(); err != nil {
			return err
		}
	}

	length := 0

	if h.ConnectionIDLength != nil {
		length = *h.ConnectionIDLength
	}

	if h.ConnectionIDGenerator != nil {
		length = h.ConnectionIDGenerator.ConnectionIDLen()
	}

	if length < 0 || length > 20 {
		return fmt.Errorf("HTTP/3 connection ID length must be between 0 and 20: %d", length)
	}

	if h.AddressFallbackDelay < 0 || h.AddressFallbackDelay > time.Minute {
		return fmt.Errorf("invalid QUIC address fallback delay")
	}

	if h.MaxResponseHeaderBytes < 0 {
		return fmt.Errorf("HTTP/3 response header limit must not be negative")
	}

	return nil
}

func (h *Options) configureClientHandshake(config *quic.Config) error {
	if h.ClientHandshake != nil {
		config.ClientHandshake = h.ClientHandshake.Clone()
	}

	if h.ClientHelloFactory == nil {
		return nil
	}

	if config.ClientHandshake == nil {
		config.ClientHandshake = &quic.ClientHandshake{}
	}

	if config.ClientHandshake.NewTLSClient != nil {
		return errors.New("configure either ClientHelloSpec/Factory or ClientHandshake.NewTLSClient")
	}

	config.ClientHandshake.NewTLSClient = quictls.Factory(h.ClientHelloFactory, h.ECHClientHelloInner)

	return nil
}
