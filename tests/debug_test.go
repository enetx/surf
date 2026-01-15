package surf_test

import (
	"fmt"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestDebugPrint(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `test response`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test Debug().Print() method
	debug := resp.Ok().Debug()
	if debug == nil {
		t.Fatal("expected debug instance")
	}

	// This will print to stdout - we test that it doesn't panic
	debug.Print()
}

func TestDebugRequest(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `request debug test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		ContentType("application/json").
		Build().Unwrap()
	req := client.Post(g.String(ts.URL), g.String(`{"test": "data"}`))

	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test Debug().Request() method
	debug := resp.Ok().Debug().Request()
	if debug == nil {
		t.Fatal("expected debug instance from Request()")
	}

	// Test chaining
	debug.Print()
}

func TestDebugRequestVerbose(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `verbose request debug test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		ContentType("application/json").
		Build().Unwrap()
	req := client.Post(g.String(ts.URL), g.String(`{"verbose": "test"}`))

	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test Debug().Request() with verbose flag
	debug := resp.Ok().Debug().Request(true)
	if debug == nil {
		t.Fatal("expected debug instance from Request(true)")
	}

	debug.Print()
}

func TestDebugResponse(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `response debug test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test Debug().Response() method
	debug := resp.Ok().Debug().Response()
	if debug == nil {
		t.Fatal("expected debug instance from Response()")
	}

	debug.Print()
}

func TestDebugResponseVerbose(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"response": "verbose debug test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().CacheBody().Build().Unwrap()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test Debug().Response() with verbose flag
	debug := resp.Ok().Debug().Response(true)
	if debug == nil {
		t.Fatal("expected debug instance from Response(true)")
	}

	debug.Print()
}

func TestDebugChaining(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-server")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"chaining": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		CacheBody().
		ContentType("application/json").
		Build().Unwrap()
	req := client.Post(g.String(ts.URL), g.String(`{"request": "data"}`))

	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test chaining Debug().Request().Response().Print()
	debug := resp.Ok().Debug().
		Request(true).
		Response(true)

	if debug == nil {
		t.Fatal("expected debug instance from chaining")
	}

	debug.Print()
}
