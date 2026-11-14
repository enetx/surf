package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf"
)

type bulkStep struct {
	ID, Method, Path, Range, SHA256 string
	Size                            int
	Status                          int
	Streaming, Echo                 bool
}

type bulkPlan struct {
	Origin string
	Warmup bulkStep
	Steps  []bulkStep
}

// This replays captured fields through the public configured transport to
// isolate QUIC mechanics. ForceHTTP3 is diagnostic; this is not a reference for
// automatic discovery, racing, browser identity selection or Fetch scheduling.
func replayBulk(planPath, fieldsPath, browser, out string) (resultErr error) {
	if browser != "chrome" && browser != "firefox" {
		return fmt.Errorf("invalid bulk browser %q", browser)
	}
	var plan bulkPlan
	var fields map[string][][2]string
	for path, target := range map[string]any{planPath: &plan, fieldsPath: &fields} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, target); err != nil {
			return err
		}
	}
	origin, err := url.Parse(plan.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || len(plan.Steps) == 0 {
		return fmt.Errorf("invalid bulk HTTPS origin or empty plan")
	}
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	keys, err := os.OpenFile(filepath.Join(out, "keys.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keys.Close()

	builder := surf.NewClient().Builder().Proxy("").Timeout(3 * time.Minute)
	if browser == "chrome" {
		builder.Impersonate().Chrome()
	} else {
		builder.Impersonate().Firefox()
	}
	// Exact replay owns all captured fields, including optional Alt-Used. In
	// particular Firefox omits Alt-Used for anonymous Fetch (credentials:omit).
	// Do not let route-header generation add a field absent from that input.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpChannel.cpp
	builder.ForceHTTP3().HTTP3Settings().ConnectionRacing(false).AltUsed(false).Set()
	client := builder.TLSConfig(&tls.Config{KeyLogWriter: keys}).Session().SecureTLS().Build().Unwrap()
	defer client.Close()

	steps := make([]bulkStep, 0, 8+len(plan.Steps))
	for i := range 8 {
		warmup := plan.Warmup
		warmup.ID = fmt.Sprintf("warm-%d", i)
		if fields[warmup.ID] != nil {
			steps = append(steps, warmup)
		}
	}
	steps = append(steps, plan.Steps...)
	report := map[string]any{
		"browser": browser, "plan": plan, "started_at": time.Now().UTC(),
		"mode": "exact captured input; forced H3; verified certificates",
	}
	defer func() {
		report["finished_at"] = time.Now().UTC()
		if resultErr != nil {
			report["error"] = resultErr.Error()
		}
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(out, "report.json"), append(encoded, '\n'), 0600)
		}
		if resultErr == nil {
			resultErr = err
		}
	}()
	attempts := make([]map[string]any, 0, len(steps))
	for _, step := range steps {
		if fields[step.ID] == nil || step.Size < 1 || step.Size > 50_000_000 ||
			(step.Method != http.MethodGet && step.Method != http.MethodPost) {
			return fmt.Errorf("missing fields or invalid bulk step %q", step.ID)
		}
		target := origin.ResolveReference(&url.URL{Path: step.Path})
		query := target.Query()
		query.Set("case", step.ID)
		target.RawQuery = query.Encode()
		var body io.Reader
		var payload []byte
		if step.Method == http.MethodPost {
			payload = bytes.Repeat([]byte("Z"), step.Size)
			body = bytes.NewReader(payload)
			if step.Streaming {
				body = io.NopCloser(body)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		req, err := http.NewRequestWithContext(ctx, step.Method, target.String(), body)
		if err != nil {
			cancel()
			return err
		}
		if step.Streaming {
			req.ContentLength = -1
		}
		var regular, pseudo []string
		for _, field := range fields[step.ID] {
			if strings.HasPrefix(field[0], ":") {
				pseudo = append(pseudo, field[0])
				if field[0] == ":authority" {
					req.Host = field[1]
				}
				continue
			}
			key := http.CanonicalHeaderKey(field[0])
			req.Header[key] = append(req.Header[key], field[1])
			regular = append(regular, field[0])
		}
		req.Header[http.HeaderOrderKey] = regular
		req.Header[http.PHeaderOrderKey] = pseudo
		start := time.Now()
		response, err := client.GetClient().Transport.RoundTrip(req)
		if err != nil {
			cancel()
			return err
		}
		data, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		cancel()
		if readErr != nil {
			return readErr
		}
		if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			return fmt.Errorf("bulk response has no verified TLS chain")
		}
		expected := step.SHA256
		if step.Method == http.MethodPost && step.Echo {
			sum := sha256.Sum256(payload)
			expected = hex.EncodeToString(sum[:])
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		status := step.Status
		if status == 0 {
			status = http.StatusOK
		}
		valid := response.ProtoMajor == 3 && response.StatusCode == status && len(data) == step.Size && digest == expected
		row := map[string]any{
			"id": step.ID, "method": step.Method, "protocol": response.Proto,
			"bytes": len(data), "sha256": digest, "expected_sha256": expected,
			"status": response.StatusCode, "duration_ms": time.Since(start).Milliseconds(), "valid": valid,
			"peer_certificates": len(response.TLS.PeerCertificates), "verified_chains": len(response.TLS.VerifiedChains),
		}
		attempts = append(attempts, row)
		report["attempts"] = attempts
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "report.json"), append(encoded, '\n'), 0600); err != nil {
			return err
		}
		fmt.Printf("%s: %s, %d bytes, valid=%v\n", step.ID, response.Proto, len(data), valid)
		if !valid {
			return fmt.Errorf("bulk step %q failed protocol/status/size/hash validation", step.ID)
		}
	}
	return nil
}
