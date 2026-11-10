package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
)

func replaySurf(path, origin, browser, protocol string, stock bool, scenario string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var requests []observedRequest
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var request observedRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return err
		}
		if request.Label == "browser" {
			requests = append(requests, request)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	expected := 11
	if scenario == "priorities" {
		expected = 3
	}
	if len(requests) != expected {
		return fmt.Errorf("browser captured %d requests, expected %d", len(requests), expected)
	}
	im := surf.NewClient().Builder().Impersonate().MacOS()
	var builder *surf.Builder
	if browser == "firefox" {
		builder = im.Firefox()
	} else {
		builder = im.Chrome()
	}
	if protocol == "h3" {
		builder.ForceHTTP3()
	} else {
		builder.ForceHTTP2()
	}
	client := builder.Session().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(15 * time.Second).Build().Unwrap()
	defer client.Close()
	for _, captured := range requests {
		if stock {
			req := client.Get(g.String(origin + captured.Path))
			req.GetRequest().Method = captured.Method
			if captured.Method == "POST" {
				req.Body(uploadBody(captured.Path, scenario))
			}
			for _, field := range captured.Fields {
				if strings.EqualFold(field.Name, "authorization") {
					req.SetHeaders(field.Name, field.Value)
				}
			}
			response := req.Do()
			if response.IsErr() {
				return response.Err()
			}
			if body := response.Ok().Body.Bytes(); body.IsErr() {
				return body.Err()
			}
			if err := response.Ok().Body.Close(); err != nil {
				return err
			}
			continue
		}
		req, err := http.NewRequest(captured.Method, origin+captured.Path, strings.NewReader(uploadBody(captured.Path, scenario)))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var priorityErr error
		// Reproduce explicit priority changes only in this isolated experiment.
		if scenario == "priorities" && captured.Path == "/priority.svg" {
			ctx = http3.WithPriorityUpdateHandler(ctx, func(updater *http3.PriorityUpdater) {
				for _, u := range []int8{1, 5, 1, 1} {
					if err := updater.Update(u, true); err != nil {
						priorityErr = err
						return
					}
				}
			})
		}
		req = req.WithContext(ctx)
		var regular, pseudo []string
		seen := make(map[string]bool)
		for _, field := range captured.Fields {
			if strings.HasPrefix(field.Name, ":") {
				if field.Name == ":authority" {
					req.Host = field.Value
				}
				pseudo = append(pseudo, field.Name)
				continue
			}
			key := http.CanonicalHeaderKey(field.Name)
			req.Header[key] = append(req.Header[key], field.Value)
			if !seen[field.Name] {
				regular = append(regular, field.Name)
				seen[field.Name] = true
			}
		}
		req.Header["Header-Order:"] = regular
		req.Header["PHeader-Order:"] = pseudo
		// Use the configured public transport directly: no navigation-header
		// middleware may add fields absent from the real browser's fetch request.
		response, err := client.GetClient().Transport.RoundTrip(req)
		if err == nil && priorityErr != nil {
			response.Body.Close()
			err = priorityErr
		}
		if err != nil {
			cancel()
			return err
		}
		_, copyErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		cancel()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
