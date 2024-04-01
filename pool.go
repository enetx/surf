package surf

import "sync"

var (
	requestPool  = sync.Pool{New: func() any { return &Request{} }}
	responsePool = sync.Pool{New: func() any { return &Response{} }}
	bodyPool     = sync.Pool{New: func() any { return &Body{} }}
)
