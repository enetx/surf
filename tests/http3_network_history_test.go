package surf_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	chromecommon "github.com/enetx/surf/profiles/chrome/common"
	firefoxcommon "github.com/enetx/surf/profiles/firefox/common"
	"github.com/stretchr/testify/require"
)

func TestChromeConnectionRacingNativeDesktopReference(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/connection_history/observations.json")
	require.NoError(t, err)
	var reference struct {
		Native struct {
			Runs []struct {
				Name   string `json:"name"`
				Delays []struct {
					Milliseconds int `json:"delay_ms"`
				} `json:"controller_delays"`
			} `json:"runs"`
		} `json:"native"`
	}
	require.NoError(t, json.Unmarshal(data, &reference))
	require.Len(t, reference.Native.Runs, 2)

	delay := chromecommon.ConnectionRacing(surf.ConnectionRacingInfo{QUICWorkedInClient: true})
	for _, run := range reference.Native.Runs {
		t.Run(run.Name, func(t *testing.T) {
			observed := 0
			for _, entry := range run.Delays {
				// DNS jobs with no supported ALPN can release TCP immediately;
				// the retained positive jobs establish the supported-pool case.
				if entry.Milliseconds > 0 {
					require.Equal(t, time.Duration(entry.Milliseconds)*time.Millisecond, delay)
					observed++
				}
			}
			require.Positive(t, observed)
		})
	}
}

func TestHTTP3ConnectionRacingClientHistoryAcrossOriginsAndClients(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			first := newRacingPeer(t, true, true, true)
			second := newRacingPeer(t, true, true, true)
			third := newRacingPeer(t, true, true, true)
			roots := x509.NewCertPool()
			for _, peer := range []*racingPeer{first, second, third} {
				roots.AddCert(peer.tcp.Certificate())
			}

			// Optional passive diagnostics for a private tcpdump capture. The
			// assertions still require ordinary certificate verification.
			var keyLog io.Writer
			if path := os.Getenv("SURF_RACING_KEYLOG"); path != "" {
				log, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				require.NoError(t, err)
				t.Cleanup(func() { log.Close() })
				keyLog = log
			}

			var mu sync.Mutex
			var observations []surf.ConnectionRacingInfo
			var delays []time.Duration
			policy := chromecommon.ConnectionRacing
			if browser == "firefox" {
				policy = firefoxcommon.ConnectionRacing
			}

			build := func() *surf.Client {
				return racingBuilder(browser).
					TLSConfig(&tls.Config{RootCAs: roots, KeyLogWriter: keyLog}).
					HTTP3Settings().
					ConnectionRacing(true).
					ConnectionRacingPolicy(func(info surf.ConnectionRacingInfo) time.Duration {
						mu.Lock()
						defer mu.Unlock()
						observations = append(observations, info)
						delay := policy(info)
						delays = append(delays, delay)
						// Prepare a first successful connection deterministically.
						// Later origins use the browser's actual policy.
						if !info.QUICWorkedInClient {
							return time.Hour
						}
						return delay
					}).Set().Build().Unwrap()
			}

			client := build()
			defer client.Close()
			request := func(client *surf.Client, url string) {
				t.Helper()
				response := client.Get(g.String(url)).Do().Unwrap()
				require.Equal(t, 3, response.GetResponse().ProtoMajor)
				require.Equal(t, g.String("ok"), response.Body.String().Unwrap())
			}

			request(client, first.url)
			request(client, second.url)
			client.CloseIdleConnections()
			request(client, third.url)

			independent := build()
			defer independent.Close()
			request(independent, first.url)

			mu.Lock()
			got := append([]surf.ConnectionRacingInfo(nil), observations...)
			gotDelays := append([]time.Duration(nil), delays...)
			mu.Unlock()

			require.Len(t, got, 4)
			require.False(t, got[0].QUICWorkedInClient)
			require.True(t, got[1].QUICWorkedInClient)
			require.True(t, got[2].QUICWorkedInClient)
			require.False(t, got[3].QUICWorkedInClient,
				"another built client must not inherit transport history")
			for _, info := range got {
				require.False(t, info.QUICWorked, "each request starts with a new origin or client")
				require.Zero(t, info.SmoothedRTT)
				require.Nil(t, info.LastQUICError)
			}

			if browser == "chrome" {
				require.Equal(t, []time.Duration{0, 350 * time.Millisecond, 350 * time.Millisecond, 0}, gotDelays)
			} else {
				require.Equal(t, []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond}, gotDelays)
			}
			require.Zero(t, first.tcpCalls.Load()+second.tcpCalls.Load()+third.tcpCalls.Load())
		})
	}
}

func TestChromeConnectionRacingSourceDelayBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		info    surf.ConnectionRacingInfo
		desktop time.Duration
		android time.Duration
	}{
		{name: "cold"},
		{
			name:    "origin success",
			info:    surf.ConnectionRacingInfo{QUICWorked: true},
			desktop: 350 * time.Millisecond,
			android: 400 * time.Millisecond,
		},
		{
			name:    "client success",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true},
			desktop: 350 * time.Millisecond,
			android: 400 * time.Millisecond,
		},
		{
			name: "origin failure",
			info: surf.ConnectionRacingInfo{QUICWorkedInClient: true, LastQUICError: errors.New("failure")},
		},
		{
			name: "RTT alone is not support",
			info: surf.ConnectionRacingInfo{SmoothedRTT: time.Millisecond},
		},
		{
			name:    "RTT",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: 20 * time.Millisecond},
			desktop: 80 * time.Millisecond,
			android: 130 * time.Millisecond,
		},
		{
			name:    "microsecond truncation",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: 3*time.Microsecond + 999*time.Nanosecond},
			desktop: 50*time.Millisecond + 4*time.Microsecond,
			android: 100*time.Millisecond + 4*time.Microsecond,
		},
		{
			name:    "missing RTT",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: -time.Second},
			desktop: 350 * time.Millisecond,
			android: 400 * time.Millisecond,
		},
		{
			name:    "zero microseconds",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: time.Nanosecond},
			desktop: 350 * time.Millisecond,
			android: 400 * time.Millisecond,
		},
		{
			name:    "Android total cap",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: 1950 * time.Millisecond},
			desktop: 2975 * time.Millisecond,
			android: 3 * time.Second,
		},
		{
			name:    "controller cap",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: 2 * time.Second},
			desktop: 3 * time.Second,
			android: 3 * time.Second,
		},
		{
			name:    "overflow",
			info:    surf.ConnectionRacingInfo{QUICWorkedInClient: true, SmoothedRTT: time.Duration(1<<63 - 1)},
			desktop: 3 * time.Second,
			android: 3 * time.Second,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.desktop, chromecommon.ConnectionRacing(tc.info))
			require.Equal(t, tc.android, chromecommon.ConnectionRacingAndroid(tc.info))
			require.Equal(t, 100*time.Millisecond, firefoxcommon.ConnectionRacing(tc.info))
		})
	}
}
