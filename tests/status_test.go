package surf_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/enetx/g"
	ehttp "github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestStatusCodeSuccess(t *testing.T) {
	t.Parallel()

	successCodes := []int{200, 201, 202, 204, 206}

	for _, code := range successCodes {
		handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
			w.WriteHeader(code)
		}

		ts := httptest.NewServer(ehttp.HandlerFunc(handler))
		defer ts.Close()

		client := surf.NewClient()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		statusCode := resp.Ok().StatusCode

		if int(statusCode) != code {
			t.Errorf("expected status code %d, got %d", code, statusCode)
		}

		if !statusCode.IsSuccess() {
			t.Errorf("expected status code %d to be success", code)
		}
	}
}

func TestStatusCodeClientError(t *testing.T) {
	t.Parallel()

	clientErrorCodes := []int{400, 401, 403, 404, 405, 409, 429}

	for _, code := range clientErrorCodes {
		handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
			w.WriteHeader(code)
		}

		ts := httptest.NewServer(ehttp.HandlerFunc(handler))
		defer ts.Close()

		client := surf.NewClient()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		statusCode := resp.Ok().StatusCode

		if int(statusCode) != code {
			t.Errorf("expected status code %d, got %d", code, statusCode)
		}

		if !statusCode.IsClientError() {
			t.Errorf("expected status code %d to be client error", code)
		}

		if statusCode.IsSuccess() {
			t.Errorf("expected status code %d to not be success", code)
		}
	}
}

func TestStatusCodeServerError(t *testing.T) {
	t.Parallel()

	serverErrorCodes := []int{500, 501, 502, 503, 504, 505}

	for _, code := range serverErrorCodes {
		handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
			w.WriteHeader(code)
		}

		ts := httptest.NewServer(ehttp.HandlerFunc(handler))
		defer ts.Close()

		client := surf.NewClient()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		statusCode := resp.Ok().StatusCode

		if int(statusCode) != code {
			t.Errorf("expected status code %d, got %d", code, statusCode)
		}

		if !statusCode.IsServerError() {
			t.Errorf("expected status code %d to be server error", code)
		}

		if statusCode.IsSuccess() {
			t.Errorf("expected status code %d to not be success", code)
		}
	}
}

func TestStatusCodeRedirect(t *testing.T) {
	t.Parallel()

	redirectCodes := []int{301, 302, 303, 307, 308}

	for _, code := range redirectCodes {
		handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
			w.WriteHeader(code)
		}

		ts := httptest.NewServer(ehttp.HandlerFunc(handler))
		defer ts.Close()

		client := surf.NewClient()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		statusCode := resp.Ok().StatusCode

		if int(statusCode) != code {
			t.Errorf("expected status code %d, got %d", code, statusCode)
		}

		if !statusCode.IsRedirection() {
			t.Errorf("expected status code %d to be redirect", code)
		}

		if statusCode.IsSuccess() {
			t.Errorf("expected status code %d to not be success", code)
		}
	}
}

func TestStatusCodeInformational(t *testing.T) {
	t.Parallel()

	// Note: 1xx codes are difficult to test with httptest as they are handled
	// differently. We'll test the classification methods with known codes.

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	statusCode := resp.Ok().StatusCode

	// Test that 200 is NOT informational
	if statusCode.IsInformational() {
		t.Error("expected 200 to not be informational")
	}
}

func TestStatusCodeString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		code     int
		expected string
	}{
		{200, "200 OK"},
		{404, "404 Not Found"},
		{500, "500 Internal Server Error"},
	}

	for _, tc := range testCases {
		handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
			w.WriteHeader(tc.code)
		}

		ts := httptest.NewServer(ehttp.HandlerFunc(handler))
		defer ts.Close()

		client := surf.NewClient()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		statusCode := resp.Ok().StatusCode
		statusStr := fmt.Sprintf("%d %s", statusCode, statusCode.Text())

		if statusStr != tc.expected {
			t.Errorf("expected status string to be %s, got %s", tc.expected, statusStr)
		}
	}
}

func TestStatusCodeComparison(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	statusCode := resp.Ok().StatusCode

	// Test equality
	if statusCode != 200 {
		t.Error("expected status code to equal 200")
	}

	// Test type conversion
	if int(statusCode) != 200 {
		t.Error("expected status code to convert to int 200")
	}
}

func TestStatusCodeRetryLogic(t *testing.T) {
	t.Parallel()

	// Test that certain status codes should trigger retries
	retryCodes := []int{429, 500, 502, 503, 504}

	for _, code := range retryCodes {
		handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
			w.WriteHeader(code)
		}

		ts := httptest.NewServer(ehttp.HandlerFunc(handler))
		defer ts.Close()

		client := surf.NewClient()
		resp := client.Get(g.String(ts.URL)).Do()

		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		statusCode := resp.Ok().StatusCode

		// These codes should typically be retryable
		shouldRetry := statusCode.IsServerError() || statusCode == 429
		if !shouldRetry {
			t.Errorf("expected status code %d to be potentially retryable", code)
		}
	}
}

func TestStatusCodeEdgeCases(t *testing.T) {
	t.Parallel()

	// Test with 418 I'm a teapot
	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.WriteHeader(418)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	statusCode := resp.Ok().StatusCode

	if int(statusCode) != 418 {
		t.Errorf("expected status code 418, got %d", statusCode)
	}

	if !statusCode.IsClientError() {
		t.Error("expected 418 to be client error")
	}

	if statusCode.IsSuccess() {
		t.Error("expected 418 to not be success")
	}
}

func TestStatusCodeDirectMethods(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		code            surf.StatusCode
		isInformational bool
		isSuccess       bool
		isRedirection   bool
		isClientError   bool
		isServerError   bool
		text            string
	}{
		{100, true, false, false, false, false, "Continue"},
		{101, true, false, false, false, false, "Switching Protocols"},
		{102, true, false, false, false, false, "Processing"},
		{199, true, false, false, false, false, ""},
		{200, false, true, false, false, false, "OK"},
		{201, false, true, false, false, false, "Created"},
		{204, false, true, false, false, false, "No Content"},
		{299, false, true, false, false, false, ""},
		{300, false, false, true, false, false, "Multiple Choices"},
		{301, false, false, true, false, false, "Moved Permanently"},
		{302, false, false, true, false, false, "Found"},
		{399, false, false, true, false, false, ""},
		{400, false, false, false, true, false, "Bad Request"},
		{401, false, false, false, true, false, "Unauthorized"},
		{404, false, false, false, true, false, "Not Found"},
		{499, false, false, false, true, false, ""},
		{500, false, false, false, false, true, "Internal Server Error"},
		{502, false, false, false, false, true, "Bad Gateway"},
		{503, false, false, false, false, true, "Service Unavailable"},
		{599, false, false, false, false, true, ""},
		{600, false, false, false, false, true, ""},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("StatusCode_%d", tc.code), func(t *testing.T) {
			if tc.code.IsInformational() != tc.isInformational {
				t.Errorf("IsInformational() for %d: expected %v, got %v", tc.code, tc.isInformational, tc.code.IsInformational())
			}
			if tc.code.IsSuccess() != tc.isSuccess {
				t.Errorf("IsSuccess() for %d: expected %v, got %v", tc.code, tc.isSuccess, tc.code.IsSuccess())
			}
			if tc.code.IsRedirection() != tc.isRedirection {
				t.Errorf("IsRedirection() for %d: expected %v, got %v", tc.code, tc.isRedirection, tc.code.IsRedirection())
			}
			if tc.code.IsClientError() != tc.isClientError {
				t.Errorf("IsClientError() for %d: expected %v, got %v", tc.code, tc.isClientError, tc.code.IsClientError())
			}
			if tc.code.IsServerError() != tc.isServerError {
				t.Errorf("IsServerError() for %d: expected %v, got %v", tc.code, tc.isServerError, tc.code.IsServerError())
			}
			if tc.code.Text() != tc.text {
				t.Errorf("Text() for %d: expected %q, got %q", tc.code, tc.text, tc.code.Text())
			}
		})
	}
}

func TestStatusCodeBoundaries(t *testing.T) {
	t.Parallel()

	// Test exact boundary values
	boundaries := []struct {
		code            surf.StatusCode
		isInformational bool
		isSuccess       bool
		isRedirection   bool
		isClientError   bool
		isServerError   bool
	}{
		{99, false, false, false, false, false},
		{100, true, false, false, false, false},
		{199, true, false, false, false, false},
		{200, false, true, false, false, false},
		{299, false, true, false, false, false},
		{300, false, false, true, false, false},
		{399, false, false, true, false, false},
		{400, false, false, false, true, false},
		{499, false, false, false, true, false},
		{500, false, false, false, false, true},
		{999, false, false, false, false, true},
	}

	for _, b := range boundaries {
		t.Run(fmt.Sprintf("Boundary_%d", b.code), func(t *testing.T) {
			if b.code.IsInformational() != b.isInformational {
				t.Errorf("IsInformational() for boundary %d: expected %v", b.code, b.isInformational)
			}
			if b.code.IsSuccess() != b.isSuccess {
				t.Errorf("IsSuccess() for boundary %d: expected %v", b.code, b.isSuccess)
			}
			if b.code.IsRedirection() != b.isRedirection {
				t.Errorf("IsRedirection() for boundary %d: expected %v", b.code, b.isRedirection)
			}
			if b.code.IsClientError() != b.isClientError {
				t.Errorf("IsClientError() for boundary %d: expected %v", b.code, b.isClientError)
			}
			if b.code.IsServerError() != b.isServerError {
				t.Errorf("IsServerError() for boundary %d: expected %v", b.code, b.isServerError)
			}
		})
	}
}
