package profiles

import (
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/enetx/g"
	"github.com/enetx/g/cmp"
	"github.com/enetx/http"
)

// ProtocolHeaders adjusts headers for the protocol used by one transport
// attempt. It receives a private header map and the HTTP major version.
// Policies must support concurrent calls and preserve explicit user values.
// Profiles with a policy supply their default pseudo-header order here;
// BuildHeaders' pseudo-header placeholders are deferred until this stage.
type ProtocolHeaders func(http.Header, int)

// HeadersApplier applies a browser preset to an ordered map for a plain HTTP
// method. Built-in adapters use a fresh request factory. BuildRequestHeaders
// accepts explicit protocol, scenario and body context for actual requests.
type HeadersApplier func(headers any, method string)

// HeadersFn is the type of a generic headers function instantiated for a concrete T ~string.
type HeadersFn[T ~string] func(*g.MapOrd[T, T], string)

// NewApplier retains the generic insert-and-sort adapter for callers supplying
// their own method tables. Built-in browser presets use NewRequestHeadersApplier
// and BuildRequestHeaders. Cache initialization remains lazy.
//
// The constructor takes the two concrete HeadersFn instantiations as separate parameters so
// callers can pass the same generic function twice and let Go infer T at each site.
func NewApplier(
	insertG HeadersFn[g.String],
	insertS HeadersFn[string],
	cache *HeaderCache,
	mobile bool,
) HeadersApplier {
	return func(h any, method string) {
		switch v := h.(type) {
		case *g.MapOrd[g.String, g.String]:
			insertG(v, method)
			SortByOrder(v, method, cache.Enums(mobile))
		case *g.MapOrd[string, string]:
			insertS(v, method)
			SortByOrder(v, method, cache.Enums(mobile))
		}
	}
}

// HeaderCache lazily builds and caches per-method header-position enums for both desktop and
// mobile header-order maps. Platform-specific pipelines can use independent caches.
// Enums(mobile) selects the configured map.
type HeaderCache struct {
	desktopOrder g.Map[string, g.Slice[string]]
	mobileOrder  g.Map[string, g.Slice[string]]

	desktopEnums g.Map[string, g.MapOrd[string, g.Int]]
	mobileEnums  g.Map[string, g.MapOrd[string, g.Int]]

	onceDesktop sync.Once
	onceMobile  sync.Once
}

// NewHeaderCache wires the cache to two header-order maps. Enums are built on first access.
func NewHeaderCache(desktop, mobile g.Map[string, g.Slice[string]]) *HeaderCache {
	return &HeaderCache{desktopOrder: desktop, mobileOrder: mobile}
}

// Enums returns the desktop or mobile enum map (lazy-built on first call).
func (c *HeaderCache) Enums(mobile bool) g.Map[string, g.MapOrd[string, g.Int]] {
	if mobile {
		c.onceMobile.Do(func() { c.mobileEnums = buildHeaderEnums(c.mobileOrder) })
		return c.mobileEnums
	}

	c.onceDesktop.Do(func() { c.desktopEnums = buildHeaderEnums(c.desktopOrder) })

	return c.desktopEnums
}

func buildHeaderEnums(order g.Map[string, g.Slice[string]]) g.Map[string, g.MapOrd[string, g.Int]] {
	enums := g.NewMap[string, g.MapOrd[string, g.Int]]()

	for method, headers := range order {
		h := g.NewMapOrd[string, g.Int]()
		headers.Iter().Enumerate().
			ForEach(func(k g.Int, v string) {
				h.Insert(v, k)
			})

		enums[method] = h
	}

	return enums
}

// SortByOrder reorders headers in-place according to HeaderCache.Enums.
// Names match without regard to case; unknown fields follow known fields in
// alphabetical order. An unknown method uses the GET enum when available.
func SortByOrder[T ~string](h *g.MapOrd[T, T], method string, enums g.Map[string, g.MapOrd[string, g.Int]]) {
	enum := enums.Get(method).UnwrapOr(enums["GET"])
	positions := g.NewMap[string, g.Int]()
	enum.Iter().ForEach(func(name string, position g.Int) { positions[strings.ToLower(name)] = position })

	h.SortByKey(func(a, b T) cmp.Ordering {
		ida := positions.Get(strings.ToLower(string(a))).UnwrapOr(g.Int(math.MaxInt))
		idb := positions.Get(strings.ToLower(string(b))).UnwrapOr(g.Int(math.MaxInt))
		order := ida.Cmp(idb)
		if ida == g.Int(math.MaxInt) && idb == g.Int(math.MaxInt) {
			return g.String(strings.ToLower(string(a))).Cmp(g.String(strings.ToLower(string(b))))
		}
		return order
	})
}

// NewRequestHeadersApplier adapts an ordered request-header factory to the
// existing HeadersApplier signature. It applies a complete HTTP/2 preset for a
// plain HTTP method; use HeaderContext for explicit protocol/body/scenario data.
// Nonempty caller values win, empty slots can receive defaults, and fields are
// ordered from the same declaration without method caches or encoded keys.
func NewRequestHeadersApplier(factory func(HeaderContext) g.MapOrd[g.String, g.String]) HeadersApplier {
	return func(headers any, method string) {
		switch fields := headers.(type) {
		case *g.MapOrd[string, string]:
			applyRequestHeaderPreset(fields, method, factory)
		case *g.MapOrd[g.String, g.String]:
			applyRequestHeaderPreset(fields, method, factory)
		}
	}
}

func applyRequestHeaderPreset[T ~string](fields *g.MapOrd[T, T], method string, factory func(HeaderContext) g.MapOrd[g.String, g.String]) {
	if fields == nil || factory == nil {
		return
	}
	req := &http.Request{Method: method, Header: make(http.Header)}
	fields.Iter().ForEach(func(name, value T) {
		if value != "" && !strings.HasPrefix(string(name), ":") {
			req.Header.Set(string(name), string(value))
		}
	})
	// This is only a header-facade layout hint. Wire serializers always use the
	// actual request body length and never trust this supplied numeric value.
	if length, err := strconv.ParseInt(req.Header.Get("Content-Length"), 10, 64); err == nil && length > 0 {
		req.ContentLength = length
	}
	preset := factory(HeaderContext{Request: req, Protocol: 2})
	positions := make(map[string]int, preset.Len())
	position := 0
	preset.Iter().ForEach(func(name, value g.String) {
		positions[strings.ToLower(name.Std())] = position
		position++
		var matched T
		present := false
		nonempty := false
		fields.Iter().ForEach(func(key, actual T) {
			if strings.EqualFold(string(key), name.Std()) {
				if !present {
					matched = key
					present = true
				}
				nonempty = nonempty || actual != ""
			}
		})
		if !present {
			fields.Insert(T(name), T(value))
		} else if !nonempty && value != "" {
			fields.Insert(matched, T(value))
		}
	})
	fields.SortByKey(func(a, b T) cmp.Ordering {
		first, ok := positions[strings.ToLower(string(a))]
		if !ok {
			first = math.MaxInt
		}
		second, ok := positions[strings.ToLower(string(b))]
		if !ok {
			second = math.MaxInt
		}
		if first != second {
			return g.Int(first).Cmp(g.Int(second))
		}
		return g.String(strings.ToLower(string(a))).Cmp(g.String(strings.ToLower(string(b)))).Then(g.String(a).Cmp(g.String(b)))
	})
}
