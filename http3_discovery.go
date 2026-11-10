package surf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/enetx/http"
)

// HTTPSRecord describes an RFC 9460 HTTPS service binding. Lookup callbacks
// must return resolved ServiceMode bindings with owned slices and honor
// cancellation. The built-in resolver follows CNAME/AliasMode chains.
type HTTPSRecord struct {
	Priority           uint16
	Target             string
	ALPN               []string
	Port               uint16
	IPv4Hint, IPv6Hint []netip.Addr
	TTL                time.Duration
	ECH                []byte
	Mandatory          []uint16
	NoDefaultALPN      bool
}

type HTTPSRecordsLookup func(context.Context, string) ([]HTTPSRecord, error)
type AlternativeServiceBackoff = func(consecutiveFailures uint32) time.Duration

func requiresTCPHTTP(req *http.Request) bool {
	if req.Method == http.MethodConnect {
		return true
	}
	for name, values := range req.Header {
		if strings.EqualFold(name, "Upgrade") {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return true
				}
			}
		}
	}
	return false
}

// Discovery learns HTTP/3 alternatives from authenticated Alt-Svc responses
// and HTTPS DNS records. Without an advertisement requests use TCP. ForceHTTP3
// retains its direct-attempt behavior. Cache and failures belong to this client.
func (h *HTTP3Settings) Discovery(enabled bool) *HTTP3Settings { h.discovery = enabled; return h }

// HTTPSRecordsLookup supplies HTTPS records from an application resolver. Nil
// uses the client's configured DNS transport and system resolver addresses.
// No public DNS provider is substituted. Proxies bypass local HTTPS discovery.
func (h *HTTP3Settings) HTTPSRecordsLookup(lookup HTTPSRecordsLookup) *HTTP3Settings {
	h.httpsRecordsLookup = lookup
	return h
}

// AlternativeServiceBackoff selects the retry delay after a failed alternative
// handshake. Cancellation and a TCP race win do not count as service failure.
// The callback must be prompt, concurrency safe, and must not reenter this client.
func (h *HTTP3Settings) AlternativeServiceBackoff(policy AlternativeServiceBackoff) *HTTP3Settings {
	h.alternativeServiceBackoff = policy
	return h
}

// ExpireFailedAlternatives discards a failed advertisement when its retry
// interval expires; a new advertisement or DNS answer is then required.
func (h *HTTP3Settings) ExpireFailedAlternatives(enabled bool) *HTTP3Settings {
	h.expireFailedAlternatives = enabled
	return h
}

type alternativeRoute struct {
	origin, address string
	expires         time.Time
	hints           []netip.Addr
	fromAltSvc      bool
	tcpAddress      string
	noTCP           bool
	ech             []byte
}
type alternativeRouteKey struct{}
type alternativeFailure struct {
	count uint32
	until time.Time
}

type httpsDiscoveryFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
}

func (d *alternativeDiscovery) resolve(ctx context.Context, origin string) (alternativeRoute, bool) {
	if route, ok := d.get(origin); ok && !d.needsDNSRefresh(origin) {
		return route, true
	}
	if ctx.Err() != nil {
		return alternativeRoute{}, false
	}
	host, _, _ := net.SplitHostPort(origin)
	if net.ParseIP(host) != nil || d.lookup == nil {
		return alternativeRoute{}, false
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return alternativeRoute{}, false
	}
	f := d.dnsFlights[origin]
	if f == nil {
		workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		f = &httpsDiscoveryFlight{done: make(chan struct{}), cancel: cancel}
		d.dnsFlights[origin] = f
		go func() {
			defer cancel()
			d.resolveUnshared(workerCtx, origin)
			d.mu.Lock()
			if d.dnsFlights[origin] == f {
				delete(d.dnsFlights, origin)
			}
			close(f.done)
			d.mu.Unlock()
		}()
	}
	f.waiters++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		f.waiters--
		if f.waiters == 0 && d.dnsFlights[origin] == f {
			f.cancel()
			delete(d.dnsFlights, origin)
			delete(d.dnsUntil, origin)
		}
		d.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return alternativeRoute{}, false
	case <-f.done:
		return d.get(origin)
	}
}

func (d *alternativeDiscovery) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, flight := range d.dnsFlights {
		flight.cancel()
	}
}

type alternativeDiscovery struct {
	mu            sync.Mutex
	entries       map[string]alternativeRoute
	failures      map[string]alternativeFailure
	dnsUntil      map[string]time.Time
	actual        map[string]alternativeRoute
	lookup        HTTPSRecordsLookup
	backoff       AlternativeServiceBackoff
	now           func() time.Time
	discardBroken bool
	dnsFlights    map[string]*httpsDiscoveryFlight
	bindings      map[string]httpsServiceBinding
	closed        bool
}

func newAlternativeDiscovery(lookup HTTPSRecordsLookup, backoff AlternativeServiceBackoff, discardBroken bool) *alternativeDiscovery {
	return &alternativeDiscovery{
		entries: make(map[string]alternativeRoute), failures: make(map[string]alternativeFailure),
		dnsUntil: make(map[string]time.Time), actual: make(map[string]alternativeRoute),
		dnsFlights: make(map[string]*httpsDiscoveryFlight), bindings: make(map[string]httpsServiceBinding),
		lookup: lookup, backoff: backoff, now: time.Now, discardBroken: discardBroken,
	}
}

func (d *alternativeDiscovery) get(origin string) (alternativeRoute, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	route, ok := d.entries[origin]
	if !ok || !d.now().Before(route.expires) {
		delete(d.entries, origin)
		return alternativeRoute{}, false
	}
	if failure := d.failures[origin+"\x00"+route.address]; d.now().Before(failure.until) {
		return alternativeRoute{}, false
	}
	return route, true
}

func (d *alternativeDiscovery) put(route alternativeRoute) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Per-client bounded history; never let response headers create unbounded state.
	if _, exists := d.entries[route.origin]; !exists && len(d.entries) >= 256 {
		for key := range d.entries {
			delete(d.entries, key)
			break
		}
	}
	d.entries[route.origin] = route
}

func (d *alternativeDiscovery) observe(origin string, response *http.Response) {
	// RFC 7838 sections 2.1 and 3.1. InsecureSkipVerify alone does not
	// authenticate an advertisement, even if the response contains certificates.
	if response == nil || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return
	}
	values := response.Header.Values("Alt-Svc")
	if len(values) == 0 {
		return
	}
	joined := strings.Join(values, ",")
	if strings.TrimSpace(joined) == "clear" {
		d.mu.Lock()
		if cached, ok := d.entries[origin]; ok && cached.fromAltSvc {
			delete(d.entries, origin)
		}
		d.mu.Unlock()
		return
	}
	var age uint64
	if a, err := strconv.ParseUint(response.Header.Get("Age"), 10, 32); err == nil {
		age = a
	}
	for _, member := range splitAltSvc(joined, ',') {
		parts := splitAltSvc(member, ';')
		protocol, authority, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if !ok || protocol != "h3" {
			continue
		}
		authority, err := strconv.Unquote(strings.TrimSpace(authority))
		if err != nil {
			continue
		}
		host, port, err := net.SplitHostPort(authority)
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			continue
		}
		if host == "" {
			host, _, _ = net.SplitHostPort(origin)
		}
		if strings.ContainsAny(host, "/\\?#@ \t\r\n\x00") {
			continue
		}
		maxAge := uint64(86400)
		valid := true
		for _, param := range parts[1:] {
			name, value, hasValue := strings.Cut(strings.TrimSpace(param), "=")
			if name != "ma" {
				continue
			}
			if !hasValue {
				valid = false
				break
			}
			if strings.HasPrefix(value, "\"") {
				value, err = strconv.Unquote(value)
				if err != nil {
					valid = false
					break
				}
			}
			maxAge, err = strconv.ParseUint(value, 10, 32)
			if err != nil {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if age >= maxAge {
			d.mu.Lock()
			delete(d.entries, origin)
			d.mu.Unlock()
			return
		}
		d.put(alternativeRoute{origin: origin, address: net.JoinHostPort(host, strconv.FormatUint(n, 10)), expires: d.now().Add(time.Duration(maxAge-age) * time.Second), fromAltSvc: true})
		return
	}
}

func splitAltSvc(s string, delimiter byte) []string {
	var result []string
	quoted, escaped, start := false, false, 0
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if quoted && s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == '"' {
			quoted = !quoted
		}
		if s[i] == delimiter && !quoted {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	return append(result, s[start:])
}

func (d *alternativeDiscovery) resolveUnshared(ctx context.Context, origin string) (alternativeRoute, bool) {
	if route, ok := d.get(origin); ok && !d.needsDNSRefresh(origin) {
		return route, true
	}
	host, port, _ := net.SplitHostPort(origin)
	if net.ParseIP(host) != nil || d.lookup == nil {
		return alternativeRoute{}, false
	}
	d.mu.Lock()
	if d.now().Before(d.dnsUntil[origin]) {
		d.mu.Unlock()
		return alternativeRoute{}, false
	}
	if len(d.dnsUntil) >= 256 {
		for key := range d.dnsUntil {
			delete(d.dnsUntil, key)
			break
		}
	}
	d.dnsUntil[origin] = d.now().Add(time.Minute)
	d.mu.Unlock()
	query := host
	if port != "443" {
		query = "_" + port + "._https." + host
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	records, err := d.lookup(lookupCtx, query)
	if err != nil {
		return alternativeRoute{}, false
	}
	var selected *HTTPSRecord
	for i := range records {
		r := &records[i]
		if r.Priority == 0 || r.TTL <= 0 {
			continue
		}
		usable := true
		for _, key := range r.Mandatory {
			if key != 0 && key != 1 && key != 2 && key != 3 && key != 4 && key != 5 && key != 6 {
				usable = false
			}
		}
		h3, tcp := bindingTransports(r)
		if !usable || !h3 && !tcp {
			continue
		}
		if selected == nil || r.Priority < selected.Priority {
			selected = r
		}
	}
	if selected == nil {
		d.clearBinding(origin)
		return d.get(origin)
	}
	target := selected.Target
	if target == "" || target == "." {
		target = host
	}
	if strings.ContainsAny(target, "/\\?#@ \t\r\n\x00") {
		return alternativeRoute{}, false
	}
	if selected.Port != 0 {
		port = strconv.Itoa(int(selected.Port))
	}
	route := alternativeRoute{origin: origin, address: net.JoinHostPort(strings.TrimSuffix(target, "."), port), expires: d.now().Add(selected.TTL)}
	route.hints = append(append([]netip.Addr(nil), selected.IPv6Hint...), selected.IPv4Hint...)
	route.ech = append([]byte(nil), selected.ECH...)
	if ctx.Err() != nil {
		return alternativeRoute{}, false
	}
	h3, tcp := bindingTransports(selected)
	d.putBinding(httpsServiceBinding{alternativeRoute: route, tcp: tcp})
	if h3 {
		d.put(route)
		return d.get(origin)
	}
	return alternativeRoute{}, false
}

func (d *alternativeDiscovery) result(route alternativeRoute, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := route.origin + "\x00" + route.address
	if err == nil {
		delete(d.failures, key)
		if _, exists := d.actual[route.origin]; !exists && len(d.actual) >= 256 {
			for key := range d.actual {
				delete(d.actual, key)
				break
			}
		}
		d.actual[route.origin] = route
		return
	}
	failure := d.failures[key]
	failure.count++
	delay := time.Minute
	if d.backoff != nil {
		delay = max(0, d.backoff(failure.count))
	}
	failure.until = d.now().Add(delay)
	if _, exists := d.failures[key]; !exists && len(d.failures) >= 256 {
		for key := range d.failures {
			delete(d.failures, key)
			break
		}
	}
	d.failures[key] = failure
	if d.discardBroken {
		if cached, ok := d.entries[route.origin]; ok && cached.address == route.address && cached.fromAltSvc {
			cached.expires = minTime(cached.expires, failure.until)
			d.entries[route.origin] = cached
		}
	}
}

func (ut *uquicTransport) roundTripDiscovered(req *http.Request) (*http.Response, error) {
	origin, err := raceAddress(req)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	route, available := ut.discovery.resolve(req.Context(), origin)
	if ut.discovery.expiredECH(origin) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errHTTPSBindingExpired
	}
	binding, bound := ut.discovery.binding(origin)
	if bound {
		if !available {
			route = binding.alternativeRoute
		}
		route.tcpAddress = binding.address
		route.noTCP = !binding.tcp
		if len(binding.ech) > 0 {
			route.ech = binding.ech
		}
	}
	attempt := req
	if available || bound {
		attempt = req.WithContext(context.WithValue(req.Context(), alternativeRouteKey{}, route))
	}
	var response *http.Response
	if available {
		response, err = ut.roundTripRacing(attempt)
	} else if route.noTCP {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errHTTPSNoTCP
	} else {
		response, err = ut.fallbackTransport.RoundTrip(attempt)
	}
	if err == nil {
		ut.discovery.observe(origin, response)
	}
	return response, err
}
