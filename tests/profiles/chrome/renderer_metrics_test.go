package chrome_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/headerorder"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

func TestChromeRendererMetricsNativeFields(t *testing.T) {
	data, err := os.ReadFile("../../testdata/wire/header_presets/chrome-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Browser  string
		Requests []struct {
			Method, Path string
			Headers      [][2]string
			Body         string            `json:"body_base64"`
			AcceptCH     string            `json:"accept_ch"`
			Hints        map[string]string `json:"available_hints"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Browser != "Chromium 158.0.8127.0" || len(fixture.Requests) != 8 {
		t.Fatalf("unexpected native reference: %q, %d requests", fixture.Browser, len(fixture.Requests))
	}
	const target = "http://127.0.0.1:32145"
	authority, _ := url.Parse(target)
	for _, recorded := range fixture.Requests {
		t.Run(recorded.Method+recorded.Path, func(t *testing.T) {
			payload, err := base64.StdEncoding.DecodeString(recorded.Body)
			if err != nil {
				t.Fatal(err)
			}
			reader := bytes.NewReader(payload)
			var body io.Reader
			if len(payload) > 0 {
				body = reader
			}
			req, err := http.NewRequest(recorded.Method, target+recorded.Path, body)
			if err != nil {
				t.Fatal(err)
			}
			// Available hint values are observed inputs, not a fabricated device,
			// viewport or network model. Ordinary defaults must come from the preset.
			for name, value := range recorded.Hints {
				req.Header.Set(name, value)
			}
			for _, field := range recorded.Headers {
				if slices.Contains([]string{header.CONTENT_TYPE, header.ORIGIN, header.REFERER}, strings.ToLower(field[0])) {
					req.Header.Set(field[0], strings.ReplaceAll(field[1], "<ORIGIN>", target))
				}
			}
			original := req.Header.Clone()
			ctx := profiles.HeaderContext{Request: req, OS: profiles.MacOS, Protocol: 1, Kind: profiles.FetchRequest}
			preset := common.BuildRequestHeaders(ctx)
			fields := req.Header.Clone()
			var order []string
			preset.Iter().ForEach(func(name, value g.String) {
				order = append(order, name.Std())
				if _, present := fields[http.CanonicalHeaderKey(name.Std())]; !present && value != "" {
					fields.Set(name.Std(), value.Std())
				}
			})
			fields.Set(header.HOST, authority.Host)
			if len(payload) > 0 {
				// Framing is delegated to the engines; use the actual bytes here,
				// never the Content-Length copied from the native oracle.
				fields.Set(header.CONTENT_LENGTH, strconv.Itoa(len(payload)))
			}
			cases := common.HeaderCase(ctx)
			var got [][2]string
			for _, field := range headerorder.Sorted(fields, headerorder.Indices(order), nil) {
				name := http.CanonicalHeaderKey(field.Key)
				if slices.Contains(cases, strings.ToLower(name)) {
					name = strings.ToLower(name)
				}
				for _, value := range field.Values {
					got = append(got, [2]string{name, value})
				}
			}
			want := make([][2]string, len(recorded.Headers))
			for i, field := range recorded.Headers {
				field[1] = strings.ReplaceAll(strings.ReplaceAll(field[1], "<AUTHORITY>", authority.Host), "<ORIGIN>", target)
				want[i] = field
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("native fields for Accept-CH %q\n got: %v\nwant: %v", recorded.AcceptCH, got, want)
			}
			if reader.Len() != len(payload) || !reflect.DeepEqual(req.Header, original) {
				t.Fatal("header preparation consumed the body or changed the input headers")
			}
		})
	}
}
