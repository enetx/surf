package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

// All browser policy is selected through Surf's ordinary fluent API. A single
// client owns the TLS cache; closing idle connections forces new handshakes
// while retaining that cache. Certificate verification remains enabled.
func probe(browser, protocol, keylog string, early, racing bool, resolver string) error {
	if browser != "chrome" && browser != "firefox" || protocol != "h2" && protocol != "h3" || keylog == "" || (early || racing) && protocol != "h3" {
		return errors.New("use -probe chrome|firefox -protocol h2|h3 -keylog NEW_PRIVATE_FILE [-early] [-racing]")
	}
	if resolver != "" {
		if _, _, err := net.SplitHostPort(resolver); err != nil {
			return fmt.Errorf("invalid DNS resolver: %w", err)
		}
	}
	file, err := os.OpenFile(keylog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	builder := surf.NewClient().Builder().Proxy("").Timeout(20 * time.Second)
	if resolver != "" {
		builder.DNS(g.String(resolver))
	}
	if browser == "chrome" {
		builder.Impersonate().Chrome()
	} else {
		builder.Impersonate().Firefox()
	}
	endpoint := "https://www.cloudflare-quic.com/cdn-cgi/trace"
	if protocol == "h2" {
		builder.ForceHTTP2()
		endpoint = "https://crypto.cloudflare.com/cdn-cgi/trace"
	} else {
		builder.ForceHTTP3()
	}
	if early {
		builder.HTTP3Settings().EarlyData(true).Set()
	}
	if racing {
		builder.HTTP3Settings().ConnectionRacing(true).Set()
	}
	built := builder.TLSConfig(&tls.Config{KeyLogWriter: file}).Session().SecureTLS().Build()
	if built.IsErr() {
		return built.Err()
	}
	client := built.Ok()
	defer client.Close()
	for attempt := 1; attempt <= 3; attempt++ {
		result := client.Get(g.String(endpoint)).Do()
		if result.IsErr() {
			return result.Err()
		}
		response := result.Ok()
		expected := "HTTP/3.0"
		if protocol == "h2" {
			expected = "HTTP/2.0"
		}
		if string(response.Proto) != expected {
			response.Body.Close()
			return fmt.Errorf("attempt %d negotiated %s, wanted %s", attempt, response.Proto, expected)
		}
		if body := response.Body.String(); body.IsErr() {
			return body.Err()
		}
		state := response.GetResponse().TLS
		if state == nil || !state.ECHAccepted || len(state.VerifiedChains) == 0 {
			return fmt.Errorf("attempt %d did not establish verified ECH", attempt)
		}
		if attempt > 1 && !state.DidResume {
			return fmt.Errorf("attempt %d did not resume", attempt)
		}
		report := struct {
			Attempt  int    `json:"attempt"`
			Protocol string `json:"protocol"`
			ECH      bool   `json:"ech_accepted"`
			Resumed  bool   `json:"resumed"`
			Verified bool   `json:"verified"`
		}{attempt, string(response.Proto), state.ECHAccepted, state.DidResume, len(state.VerifiedChains) > 0}
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
		client.CloseIdleConnections()
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}
