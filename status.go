package surf

import "net/http"

// StatusCode represents an HTTP status code with convenient classification methods.
// Extends the basic integer status code with methods to easily identify the response category.
type StatusCode int

// IsInformational returns true if the status code is in the informational range [100, 200].
func (s StatusCode) IsInformational() bool { return s >= 100 && s < 200 }

// IsSuccess returns true if the status code indicates a successful response [200, 300].
func (s StatusCode) IsSuccess() bool { return s >= 200 && s < 300 }

// IsRedirection returns true if the status code indicates a redirection [300, 400].
func (s StatusCode) IsRedirection() bool { return s >= 300 && s < 400 }

// IsClientError returns true if the status code indicates a client error [400, 500].
func (s StatusCode) IsClientError() bool { return s >= 400 && s < 500 }

// IsServerError returns true if the status code indicates a server error [500, ∞].
func (s StatusCode) IsServerError() bool { return s >= 500 }

// Text returns the textual representation of the status code.
func (s StatusCode) Text() string { return http.StatusText(int(s)) }
