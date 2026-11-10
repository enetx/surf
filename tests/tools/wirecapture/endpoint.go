package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/enetx/g"
)

func probeSurfEndpoint(endpoint, directory, browser, profileOS, protocol string) error {
	if directory == "" {
		return fmt.Errorf("out directory required")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	builder := browserBuilder(browser, profileOS).SecureTLS()
	major := 2
	switch protocol {
	case "h1":
		builder.ForceHTTP1()
		major = 1
	case "h2":
		builder.ForceHTTP2()
	case "h3":
		builder.ForceHTTP3()
		major = 3
	default:
		return fmt.Errorf("unsupported endpoint protocol: %s", protocol)
	}
	client := builder.Timeout(30 * time.Second).Build().Unwrap()
	defer client.Close()
	result := client.Get(g.String(endpoint)).Do()
	if result.IsErr() {
		return result.Err()
	}
	response := result.Ok()
	if response.StatusCode != 200 || response.GetResponse().ProtoMajor != major {
		return fmt.Errorf("endpoint returned %d over %s", response.StatusCode, response.GetResponse().Proto)
	}
	body := response.Body.Bytes()
	if body.IsErr() {
		return body.Err()
	}
	if !json.Valid(body.Ok()) {
		return fmt.Errorf("endpoint returned invalid JSON")
	}
	return os.WriteFile(filepath.Join(directory, "surf-endpoint.json"), body.Ok(), 0600)
}
