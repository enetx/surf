package chrome_test

import (
	"slices"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles/chrome"
)

func TestHeaders_POST(t *testing.T) {
	t.Run("POST method sets correct headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.Headers(&headers, http.MethodPost)

		if v := headers.Get(header.ACCEPT); v.Unwrap() != "*/*" {
			t.Errorf("Expected Accept header to be '*/*', got %s", v.Unwrap())
		}

		if v := headers.Get(header.CACHE_CONTROL); v.Unwrap() != "no-cache" {
			t.Errorf("Expected Cache-Control header to be 'no-cache', got %s", v.Unwrap())
		}

		if v := headers.Get(header.CONTENT_TYPE); v.Unwrap() != "" {
			t.Errorf("Expected Content-Type header to be empty, got %s", v.Unwrap())
		}

		if v := headers.Get(header.PRAGMA); v.Unwrap() != "no-cache" {
			t.Errorf("Expected Pragma header to be 'no-cache', got %s", v.Unwrap())
		}

		if v := headers.Get(header.PRIORITY); v.Unwrap() != "u=1, i" {
			t.Errorf("Expected Priority header to be 'u=1, i', got %s", v.Unwrap())
		}

		if v := headers.Get(header.SEC_FETCH_DEST); v.Unwrap() != "empty" {
			t.Errorf("Expected Sec-Fetch-Dest header to be 'empty', got %s", v.Unwrap())
		}

		if v := headers.Get(header.SEC_FETCH_MODE); v.Unwrap() != "cors" {
			t.Errorf("Expected Sec-Fetch-Mode header to be 'cors', got %s", v.Unwrap())
		}

		if v := headers.Get(header.SEC_FETCH_SITE); v.Unwrap() != "same-origin" {
			t.Errorf("Expected Sec-Fetch-Site header to be 'same-origin', got %s", v.Unwrap())
		}
	})

	t.Run("POST method header order", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()

		headers.Insert(":method", "POST")
		headers.Insert(":authority", "127.0.0.1")
		headers.Insert(":scheme", "https")
		headers.Insert(":path", "/api")
		headers.Insert(header.CONTENT_LENGTH, "100")
		headers.Insert(header.USER_AGENT, "Mozilla/5.0")
		headers.Insert(header.REFERER, "https://127.0.0.1")
		headers.Insert(header.COOKIE, "session=abc")
		headers.Insert(header.ACCEPT_ENCODING, "gzip, deflate")
		headers.Insert(header.ACCEPT_LANGUAGE, "en-US")
		headers.Insert(header.ORIGIN, "https://127.0.0.1")

		chrome.Headers(&headers, http.MethodPost)

		expectedOrder := []string{
			":method",
			":authority",
			":scheme",
			":path",
			header.CONTENT_LENGTH,
			header.PRAGMA,
			header.CACHE_CONTROL,
			header.USER_AGENT,
			header.CONTENT_TYPE,
			header.ACCEPT,
			header.ORIGIN,
			header.SEC_FETCH_SITE,
			header.SEC_FETCH_MODE,
			header.SEC_FETCH_DEST,
			header.REFERER,
			header.ACCEPT_ENCODING,
			header.ACCEPT_LANGUAGE,
			header.COOKIE,
			header.PRIORITY,
		}

		keys := headers.Keys()

		for i, expected := range expectedOrder {
			if g.Int(i) >= keys.Len() {
				t.Errorf("Missing header at position %d: expected %s", i, expected)
				continue
			}

			if !headers.Contains(expected) {
				continue
			}

			found := slices.Contains(keys, expected)

			if !found {
				t.Errorf("Header %s not found in the ordered map", expected)
			}
		}
	})

	t.Run("POST method doesn't set GET-specific headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.Headers(&headers, http.MethodPost)

		if headers.Contains(header.SEC_FETCH_USER) {
			t.Errorf("Sec-Fetch-User header should not be set for POST requests")
		}

		if headers.Contains(header.UPGRADE_INSECURE_REQUESTS) {
			t.Errorf("Upgrade-Insecure-Requests header should not be set for POST requests")
		}
	})

	t.Run("POST method preserves existing headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()

		headers.Insert("X-Custom-Header", "custom-value")
		headers.Insert(header.AUTHORIZATION, "Bearer token123")

		chrome.Headers(&headers, http.MethodPost)

		if v := headers.Get("X-Custom-Header"); v.Unwrap() != "custom-value" {
			t.Errorf("Expected X-Custom-Header to be preserved, got %s", v.Unwrap())
		}

		if v := headers.Get(header.AUTHORIZATION); v.Unwrap() != "Bearer token123" {
			t.Errorf("Expected Authorization header to be preserved, got %s", v.Unwrap())
		}
	})
}
