package surf

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/profiles"
)

type requestHeadersPolicy func(*http.Request, int)

// requestHeaderProfile is an immutable selection, captured when a profile is
// configured. Requests never resolve profile headers through the mutable Builder.
type requestHeaderProfile struct {
	variant profiles.Variant
	os      profiles.OSKey
}

type (
	profileHeaderKey      struct{}
	profileRedirectKey    struct{}
	profileBodyDroppedKey struct{}
	profileHeaderState    struct {
		generated        http.Header
		bodyDropped      bool
		kind             profiles.RequestKind
		redirectResponse any // One hop's *http.Response or *net/http.Response.
	}
)

// Fetch selects a browser's ordinary fetch header preset, such as an API request.
// GET and HEAD default to document navigation; call Fetch to use fetch defaults
// for Accept, Fetch Metadata and Priority instead. Other methods already default
// to fetch, so a normal POST API request does not need this call.
//
// The HTTP method and body are configured by Get/Post/etc. and Body/StreamingBody.
// The selected scenario survives redirects, including HTTP origins where browsers
// omit Fetch Metadata. Explicit header values and ordered maps take precedence.
//
//	client.Get(url).Fetch().Do()
func (req *Request) Fetch() *Request { return req.withRequestKind(profiles.FetchRequest) }

// Navigation selects a browser's document-navigation header preset. Use it for
// a POST that represents form navigation rather than an API fetch: its Accept,
// Fetch Metadata, Priority and cache defaults can differ from ordinary POST.
// GET and HEAD already default to navigation and usually do not need this call.
//
// Get/Post/etc. and Body/Multipart still configure the HTTP method and payload.
// The scenario survives redirects; metadata is emitted only where the browser
// normally sends it. Explicit header values and ordered maps take precedence.
//
//	client.Post(url).Navigation().Body("name=surf").Do()
func (req *Request) Navigation() *Request { return req.withRequestKind(profiles.NavigationRequest) }

func (req *Request) withRequestKind(kind profiles.RequestKind) *Request {
	if req.err == nil {
		req.request = req.request.WithContext(profiles.WithRequestKind(req.request.Context(), kind))
	}
	return req
}

func profileHeaderValues(h http.Header, name string) ([]string, bool) {
	var values []string
	present := false

	for key, v := range h {
		if strings.EqualFold(key, name) {
			present = true
			values = append(values, v...)
		}
	}

	return values, present
}

func hasProfileHeader(h http.Header, name string) bool {
	_, present := profileHeaderValues(h, name)
	return present
}

func isHeaderMetadata(name string) bool {
	return strings.EqualFold(name, http.HeaderOrderKey) || strings.EqualFold(name, http.PHeaderOrderKey) ||
		strings.EqualFold(name, http.HeaderCaseKey)
}

func deleteProfileHeader(h http.Header, name string) {
	for key := range h {
		if strings.EqualFold(key, name) {
			delete(h, key)
		}
	}
}

func previousProfileHeaders(req *http.Request) *profileHeaderState {
	state, _ := req.Context().Value(profileHeaderKey{}).(*profileHeaderState)
	// The HTTP client copies the initial context on each redirect. At a new hop,
	// use the preceding attempt's state; later preparations use this hop's state
	// so explicit changes made by middleware keep their ownership.
	if req.Response != nil && req.Response.Request != nil && (state == nil || state.redirectResponse != req.Response) {
		if previous, _ := req.Response.Request.Context().Value(profileHeaderKey{}).(*profileHeaderState); previous != nil {
			return previous
		}
	}

	return state
}

func profileRedirectResponse(req *http.Request) any {
	if req.Response != nil {
		return req.Response
	}
	return req.Context().Value(profileRedirectKey{})
}

func (p *requestHeaderProfile) context(req *http.Request, major int) profiles.HeaderContext {
	info := profiles.HeaderContext{
		Request:  req,
		OS:       p.os,
		Protocol: major,
		Redirect: profileRedirectResponse(req) != nil,
	}

	kind, selected := profiles.RequestKindFromContext(req.Context())
	info.Kind = kind
	if !selected && info.Redirect {
		if previous := previousProfileHeaders(req); previous != nil {
			info.Kind = previous.kind
		}
	}

	if attempt := previousClientHintAttempt(req); attempt != nil {
		info.CriticalCH = attempt.restarted
	}

	return info
}

func (p *requestHeaderProfile) headers(req *http.Request, major int) g.MapOrd[g.String, g.String] {
	if p.variant.BuildRequestHeaders != nil {
		return p.variant.BuildRequestHeaders(p.context(req, major))
	}

	h := g.NewMapOrd[g.String, g.String]()
	if p.variant.BuildHeaders != nil {
		if legacy := p.variant.BuildHeaders(p.os); legacy != nil {
			h = legacy.Clone()
		}
	}

	if p.variant.Headers != nil {
		p.variant.Headers(&h, req.Method)
	}

	return h
}

// logical applies only missing values and tracks its generated defaults. No
// ordering metadata is ever written to the logical request by this path.
func (p *requestHeaderProfile) logical(req *http.Request) *http.Request {
	clone := *req
	clone.Header = req.Header.Clone()
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}

	redirectResponse := profileRedirectResponse(req)
	redirected := redirectResponse != nil

	old := previousProfileHeaders(req)
	dropped, _ := req.Context().Value(profileBodyDroppedKey{}).(bool)
	if old != nil {
		dropped = dropped || old.bodyDropped
	}

	if req.Response != nil && req.Response.Request != nil && req.Method != req.Response.Request.Method &&
		(req.Method == http.MethodGet || req.Method == http.MethodHead) &&
		(req.Body == nil || req.Body == http.NoBody) {
		dropped = true
	}

	// Both HTTP clients recopy initial entity fields at every redirect. Remove
	// them once per hop after a body drop, before application middleware can add
	// replacement fields. A later preparation of the same hop must preserve those.
	if dropped && redirected && (old == nil || old.redirectResponse != redirectResponse) {
		for _, name := range []string{"content-length", "content-type", "content-encoding", "content-language", "content-location", "origin"} {
			deleteProfileHeader(clone.Header, name)
		}
	}

	generated := make(http.Header)
	retained := make(http.Header)

	if old != nil {
		for name, value := range old.generated {
			actual, present := profileHeaderValues(clone.Header, name)
			if redirected && (!present || slices.Equal(actual, value)) &&
				(strings.EqualFold(name, "cache-control") || strings.EqualFold(name, "pragma")) {
				retained[name] = slices.Clone(value)
			}
			if present && slices.Equal(actual, value) {
				deleteProfileHeader(clone.Header, name)
			}
		}
	}

	kind := profiles.FetchRequest
	if p.context(&clone, 0).Navigation() {
		kind = profiles.NavigationRequest
	}
	// Cache validation belongs to the operation, while metadata and encodings
	// are rebuilt for each destination. Kind carries navigation/fetch even when
	// the new origin cannot receive Fetch Metadata.
	if old != nil && kind == old.kind {
		for name, values := range retained {
			if !hasProfileHeader(clone.Header, name) {
				clone.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
				generated[name] = slices.Clone(values)
			}
		}
	}
	defaults := p.headers(&clone, 0)
	defaults.Iter().ForEach(func(key, value g.String) {
		name := key.Lower().Std()
		if name == "" || strings.HasPrefix(name, ":") || value == "" || isHeaderMetadata(name) {
			return
		}

		if _, present := profileHeaderValues(clone.Header, name); present {
			return
		}

		clone.Header.Set(name, value.Std())
		generated[name] = []string{value.Std()}
	})

	return clone.WithContext(
		context.WithValue(
			clone.Context(),
			profileHeaderKey{},
			&profileHeaderState{
				generated:        generated,
				bodyDropped:      dropped,
				kind:             kind,
				redirectResponse: redirectResponse,
			},
		),
	)
}

// explicitProfileHeader preserves ownership even when a public setter supplies
// exactly the value originally generated by the profile or hint negotiation.
func (req *Request) explicitProfileHeader(name string) {
	ctx := req.request.Context()
	changed := false
	if old := previousProfileHeaders(req.request); old != nil && hasProfileHeader(old.generated, name) {
		state := *old
		state.generated = old.generated.Clone()
		deleteProfileHeader(state.generated, name)
		ctx = context.WithValue(ctx, profileHeaderKey{}, &state)
		changed = true
	}
	if old := previousClientHintAttempt(req.request); old != nil && hasProfileHeader(old.generated, name) {
		state := *old
		state.generated = old.generated.Clone()
		deleteProfileHeader(state.generated, name)
		ctx = context.WithValue(ctx, clientHintAttemptKey{}, &state)
		changed = true
	}
	if changed {
		req.request = req.request.WithContext(ctx)
	}
}

// apply is the sole final profile layout step on a private transport attempt.
// Regular order, pseudo order and HTTP/1 casing retain independent user ownership.
func (p *requestHeaderProfile) apply(req *http.Request, major int) {
	*req = *p.logical(req)
	if state := previousProfileHeaders(req); state != nil {
		*req = *req.WithContext(profiles.WithRequestKind(req.Context(), state.kind))
	}

	h := p.headers(req, major)
	var regular, pseudo []string

	h.Iter().ForEach(func(key, value g.String) {
		name := key.Lower().Std()
		if name == "" || isHeaderMetadata(name) {
			return
		}

		if strings.HasPrefix(name, ":") {
			pseudo = append(pseudo, name)
			return
		}

		regular = append(regular, name)
		if value != "" {
			if _, present := profileHeaderValues(req.Header, name); !present {
				req.Header.Set(name, value.Std())
			}
		}
	})

	// A preset can omit an automatic zero-length field by leaving out its
	// position. A nil value suppresses only zero-body synthesis in the engines;
	// nonempty and streaming request framing always follows the actual body.
	if p.variant.BuildRequestHeaders != nil && req.ContentLength == 0 && (req.Body == nil || req.Body == http.NoBody) &&
		!slices.Contains(regular, "content-length") &&
		!hasProfileHeader(req.Header, "content-length") {
		req.Header["Content-Length"] = nil
	}

	if p.variant.BuildRequestHeaders == nil {
		// Preserve explicit input around the previous mutating callback contract.
		explicit := make(http.Header)
		for _, key := range []string{http.HeaderOrderKey, http.PHeaderOrderKey, http.HeaderCaseKey} {
			if values, present := req.Header[key]; present {
				explicit[key] = slices.Clone(values)
			}
		}

		setProfileMetadata(req.Header, http.HeaderOrderKey, regular)
		if major != 1 && len(pseudo) > 0 {
			setProfileMetadata(req.Header, http.PHeaderOrderKey, pseudo)
		}

		if p.variant.ProtocolHeaders != nil {
			p.variant.ProtocolHeaders(req.Header, major)
		}

		if p.variant.RequestHeaders != nil {
			p.variant.RequestHeaders(req, major)
		}

		if p.variant.ClientHintsOrder != nil {
			p.variant.ClientHintsOrder(req, p.context(req, major).CriticalCH)
		}

		maps.Copy(req.Header, explicit)
	} else {
		setProfileMetadata(req.Header, http.HeaderOrderKey, regular)
		if major != 1 && len(pseudo) > 0 {
			setProfileMetadata(req.Header, http.PHeaderOrderKey, pseudo)
		}
	}

	if major == 1 && p.variant.HeaderCase != nil {
		if _, explicit := req.Header[http.HeaderCaseKey]; !explicit {
			req.Header[http.HeaderCaseKey] = slices.Clone(p.variant.HeaderCase(p.context(req, major)))
		}
	}
}

func setProfileMetadata(headers http.Header, name string, values []string) {
	if _, explicit := headers[name]; !explicit {
		headers[name] = slices.Clone(values)
	}
}
