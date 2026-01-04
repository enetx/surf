package socks4

import (
	"errors"
	"testing"
)

func TestErrDialFailed(t *testing.T) {
	inner := errors.New("inner error")
	err := &ErrDialFailed{err: inner}

	if err.Error() == "" {
		t.Fatal("Error() returned empty string")
	}

	if !errors.Is(err, inner) {
		t.Fatal("Unwrap() does not return inner error")
	}
}

func TestErrHostUnknown(t *testing.T) {
	inner := errors.New("inner")
	err := &ErrHostUnknown{msg: "example.com", err: inner}

	if err.Error() == "" {
		t.Fatal("Error() returned empty string")
	}

	if !errors.Is(err, inner) {
		t.Fatal("Unwrap() does not return inner error")
	}
}

func TestErrBuffer(t *testing.T) {
	inner := errors.New("buffer fail")
	err := &ErrBuffer{err: inner}

	if err.Error() != "unable write into buffer" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}

	if !errors.Is(err, inner) {
		t.Fatal("Unwrap() does not return inner error")
	}
}

func TestErrIO(t *testing.T) {
	inner := errors.New("io fail")
	err := &ErrIO{err: inner}

	if err.Error() != "io error" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}

	if !errors.Is(err, inner) {
		t.Fatal("Unwrap() does not return inner error")
	}
}

func TestErrWrongAddr(t *testing.T) {
	inner := errors.New("addr fail")
	err := &ErrWrongAddr{msg: "1.2.3.4:80", err: inner}

	if err.Error() == "" {
		t.Fatal("Error() returned empty string")
	}

	if !errors.Is(err, inner) {
		t.Fatal("Unwrap() does not return inner error")
	}
}

func TestErrWrongNetwork(t *testing.T) {
	err := &ErrWrongNetwork{}

	if err.Error() != "network should be tcp or tcp4" {
		t.Fatal("unexpected Error() message")
	}
}

func TestErrConnRejected(t *testing.T) {
	err := &ErrConnRejected{}

	if err.Error() != "connection to remote host was rejected" {
		t.Fatal("unexpected Error() message")
	}
}

func TestErrIdentRequired(t *testing.T) {
	err := &ErrIdentRequired{}

	if err.Error() != "valid ident required" {
		t.Fatal("unexpected Error() message")
	}
}

func TestErrInvalidResponse(t *testing.T) {
	err := &ErrInvalidResponse{resp: 0xAB}

	if err.Error() != "unknown socks4 server response 0xab" {
		t.Fatal("unexpected Error() message")
	}
}
