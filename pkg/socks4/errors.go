package socks4

import "fmt"

type (
	ErrWrongNetwork    struct{}
	ErrConnRejected    struct{}
	ErrIdentRequired   struct{}
	ErrDialFailed      struct{ err error }
	ErrBuffer          struct{ err error }
	ErrIO              struct{ err error }
	ErrInvalidResponse struct{ resp byte }

	ErrWrongAddr struct {
		msg string
		err error
	}

	ErrHostUnknown struct {
		msg string
		err error
	}
)

func (e *ErrDialFailed) Error() string { return fmt.Sprintf("socks4 dial %v", e.err) }
func (e *ErrDialFailed) Unwrap() error { return e.err }

func (e *ErrHostUnknown) Error() string {
	return fmt.Sprintf("unable to find IP address of host %s", e.msg)
}
func (e *ErrHostUnknown) Unwrap() error { return e.err }

func (e *ErrBuffer) Error() string { return "unable write into buffer" }
func (e *ErrBuffer) Unwrap() error { return e.err }

func (e *ErrIO) Error() string { return "io error" }
func (e *ErrIO) Unwrap() error { return e.err }

func (e *ErrWrongAddr) Error() string { return fmt.Sprintf("wrong addr: %s, error: %v", e.msg, e.err) }
func (e *ErrWrongAddr) Unwrap() error { return e.err }

func (e *ErrWrongNetwork) Error() string { return "network should be tcp or tcp4" }

func (e *ErrConnRejected) Error() string  { return "connection to remote host was rejected" }
func (e *ErrIdentRequired) Error() string { return "valid ident required" }
func (e *ErrInvalidResponse) Error() string {
	return fmt.Sprintf("unknown socks4 server response 0x%02x", e.resp)
}
