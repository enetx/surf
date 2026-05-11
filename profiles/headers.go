package profiles

import (
	"sync"

	"github.com/enetx/g"
	"github.com/enetx/g/cmp"
)

// HeadersApplier applies the browser-specific request-header pipeline (insert defaults +
// reorder by header-order map) to a request header map. Form-factor (desktop/mobile) is baked
// into each applier instance — Variant.Desktop and Variant.Mobile carry different appliers.
type HeadersApplier func(headers any, method string)

// HeadersFn is the type of a generic headers function instantiated for a concrete T ~string.
type HeadersFn[T ~string] func(*g.MapOrd[T, T], string)

// NewApplier wraps a browser-specific header-insert pair with the standard "insert, then
// reorder by per-method enum" pipeline shared by every profile. The form factor (desktop/mobile)
// is baked in via cache.Enums(mobile); the lookup runs on each call so HeaderCache lazy-init is
// preserved.
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
// mobile header-order maps. Each browser profile constructs one HeaderCache from its own
// headerOrderDesktop / headerOrderMobile literals. The dispatcher asks for enums via Enums(mobile).
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
		headers.Iter().Enumerate().Collect().Iter().
			ForEach(func(k g.Int, v string) {
				h.Insert(v, k)
			})

		enums[method] = h
	}

	return enums
}

// SortByOrder reorders headers in-place according to the per-method enum positions returned
// by HeaderCache.Enums. Profile packages call it from headersDesktop / headersMobile after the
// browser-specific Insert step. Falls back to the GET enum when method is not present.
func SortByOrder[T ~string](h *g.MapOrd[T, T], method string, enums g.Map[string, g.MapOrd[string, g.Int]]) {
	enum := enums.Get(method).UnwrapOr(enums["GET"])

	h.SortByKey(func(a, b T) cmp.Ordering {
		ida := enum.Get(string(a))
		idb := enum.Get(string(b))
		return ida.UnwrapOrDefault().Cmp(idb.UnwrapOrDefault())
	})
}
