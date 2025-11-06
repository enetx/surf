package firefox

import (
	"crypto/rand"
	"encoding/binary"
	"net/http"

	"github.com/enetx/g"
	"github.com/enetx/g/cmp"
	"github.com/enetx/surf/header"
)

// Firefox implementation: https://github.com/mozilla/gecko-dev/blob/master/dom/html/HTMLFormSubmission.cpp#L355
func Boundary() g.String {
	// C++
	// mBoundary.AssignLiteral("----geckoformboundary");
	// mBoundary.AppendInt(mozilla::RandomUint64OrDie(), 16);
	// mBoundary.AppendInt(mozilla::RandomUint64OrDie(), 16);

	// prefix := "----geckoformboundary"
	// var num1, num2 uint64
	// binary.Read(rand.Reader, binary.BigEndian, &num1)
	// binary.Read(rand.Reader, binary.BigEndian, &num2)
	// return g.Sprintf("%s%x%x", prefix, num1, num2)

	////////////////////////////////////////////////////////////////////////////

	// C++
	// mBoundary.AssignLiteral("---------------------------");
	// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));
	// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));
	// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));

	prefix := g.String("---------------------------")

	var builder g.Builder
	builder.WriteString(prefix)

	for range 3 {
		var b [4]byte
		rand.Read(b[:])
		builder.WriteString(g.Int(binary.LittleEndian.Uint32(b[:])).String())
	}

	return builder.String()
}

var headerOrder = g.Map[string, g.Slice[string]]{
	http.MethodGet: {
		":method",
		":path",
		":authority",
		":scheme",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.AUTHORIZATION,
		header.COOKIE,
		header.UPGRADE_INSECURE_REQUESTS,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_USER,
		header.PRIORITY,
	},

	http.MethodPost: {
		":method",
		":path",
		":authority",
		":scheme",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.CONTENT_TYPE,
		header.AUTHORIZATION,
		header.CONTENT_LENGTH,
		header.ORIGIN,
		header.COOKIE,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.PRIORITY,
		header.PRAGMA,
		header.CACHE_CONTROL,
	},
}

func Headers[T ~string](headers *g.MapOrd[T, T], method string) {
	switch method {
	case http.MethodPost:
		headers.Set(header.ACCEPT, "*/*")
		headers.Set(header.CACHE_CONTROL, "no-cache")
		headers.Set(header.CONTENT_TYPE, "")
		headers.Set(header.PRAGMA, "no-cache")
		headers.Set(header.PRIORITY, "u=1, i")
		headers.Set(header.SEC_FETCH_DEST, "empty")
		headers.Set(header.SEC_FETCH_MODE, "cors")
		headers.Set(header.SEC_FETCH_SITE, "same-origin")
	default:
		headers.Set(header.ACCEPT, "application/json")
		headers.Set(header.PRIORITY, "u=1, i")
		headers.Set(header.SEC_FETCH_DEST, "empty")
		headers.Set(header.SEC_FETCH_MODE, "cors")
		headers.Set(header.SEC_FETCH_SITE, "same-site")
	}

	headers.SortByKey(func(a, b T) cmp.Ordering {
		m := headerOrder.Get(method).UnwrapOr(headerOrder[http.MethodGet])

		enum := m.Iter().Enumerate().Collect().Invert()
		ida := enum.Get(string(a))
		idb := enum.Get(string(b))

		return ida.UnwrapOrDefault().Cmp(idb.UnwrapOrDefault())
	})
}

// HeadersUB for UB Web
func HeadersUB[T ~string](headers *g.MapOrd[T, T], method string) {
	switch method {
	case http.MethodPost:
		headers.Set(header.ACCEPT, "*/*")
		headers.Set(header.CACHE_CONTROL, "no-cache")
		headers.Set(header.CONTENT_TYPE, "")
		headers.Set(header.PRAGMA, "no-cache")
		headers.Set(header.PRIORITY, "u=1, i")
		headers.Set(header.SEC_FETCH_DEST, "empty")
		headers.Set(header.SEC_FETCH_MODE, "cors")
		headers.Set(header.SEC_FETCH_SITE, "same-origin")
	default:
		headers.Set(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		headers.Set(header.PRIORITY, "u=0, i")
		headers.Set(header.CACHE_CONTROL, "max-age=0")
		headers.Set(header.SEC_FETCH_DEST, "document")
		headers.Set(header.SEC_FETCH_MODE, "navigate")
		headers.Set(header.SEC_FETCH_SITE, "same-origine")
		headers.Set(header.SEC_FETCH_USER, "?1")
		headers.Set(header.UPGRADE_INSECURE_REQUESTS, "1")
	}

	headers.SortByKey(func(a, b T) cmp.Ordering {
		m := headerOrder.Get(method).UnwrapOr(headerOrder[http.MethodGet])

		enum := m.Iter().Enumerate().Collect().Invert()
		ida := enum.Get(string(a))
		idb := enum.Get(string(b))

		return ida.UnwrapOrDefault().Cmp(idb.UnwrapOrDefault())
	})
}
