package surf

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http"
)

// cacheDialerStats contains statistics of a dialer's cache usage.
type cacheDialerStats struct {
	totalConn          int64 // Total number of connections made.
	cacheMiss          int64 // Number of cache misses.
	cacheHit           int64 // Number of cache hits.
	dnsQuery           int64 // Total DNS queries made.
	successfulDNSQuery int64 // Number of successful DNS queries.
}

// cacheItem describes a cached DNS result.
type cacheItem struct {
	expirationTime time.Time    // Expiration time of the cached entry.
	host           string       // Hostname associated with the cache entry.
	ips            []net.IPAddr // IP addresses associated with the hostname.
	usageCount     int64        // Number of times the cache entry has been used.
	maxUsageCount  int64        // Maximum allowed usage count for the cache entry.
}

// newCacheItem creates a new cacheItem with the given parameters.
func newCacheItem(host string, ips []net.IPAddr, ttl time.Duration, maxUsageCount int64) *cacheItem {
	return &cacheItem{
		host:           host,
		ips:            ips,
		expirationTime: time.Now().Add(ttl),
		maxUsageCount:  maxUsageCount,
	}
}

// ip returns an ip and a bool value which indicates whether the cache is valid.
func (i *cacheItem) ip() (net.IPAddr, bool) {
	n := len(i.ips)
	if n == 0 {
		return net.IPAddr{}, false
	}

	count := atomic.AddInt64(&i.usageCount, 1)
	index := int(count-1) % n

	return i.ips[index], i.maxUsageCount >= count && time.Now().Before(i.expirationTime)
}

// dialer is a struct that holds configurations for a DNS caching and dialer mechanism.
type dialer struct {
	cache             g.Map[string, *cacheItem] // DNS cache storage.
	dialer            *net.Dialer               // Network dialer.
	resolveChannels   g.Map[string, chan error] // Channels for resolving DNS queries.
	resolver          *net.Resolver             // DNS resolver.
	stats             cacheDialerStats          // Statistics for dialer and cache usage.
	cacheDuration     time.Duration             // Duration for caching DNS results.
	forceRefreshTimes int64                     // Number of times to force refresh DNS.
	lock              sync.RWMutex              // Lock for protecting cache and stats.
	chanLock          sync.Mutex                // Lock for protecting resolveChannels.
}

// cacheDialer creates a dialer with dns cache.
func (c *Client) cacheDialer() *dialer {
	cd := &dialer{
		dialer:            c.dialer,
		resolver:          c.dialer.Resolver,
		cache:             g.NewMap[string, *cacheItem](),
		resolveChannels:   g.NewMap[string, chan error](),
		cacheDuration:     c.opt.dnsCacheTTL,
		forceRefreshTimes: c.opt.dnsCacheMaxUsage,
	}

	c.transport.(*http.Transport).DialContext = cd.DialContext
	c.opt.dnsCacheStats = &cd.stats

	return cd
}

// DialContext is a method that implements the Dialer interface and handles DNS caching and dialing.
func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	atomic.AddInt64(&d.stats.totalConn, 1)

	if (network == "tcp" || network == "tcp4") && address != "" {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		if host != "" {
			ip, err := d.resolveHost(ctx, host)
			if err != nil {
				atomic.AddInt64(&d.stats.cacheMiss, 1)
				return nil, err
			}

			atomic.AddInt64(&d.stats.cacheHit, 1)

			address = net.JoinHostPort(ip.String(), port)
		}
	}

	return d.dialer.DialContext(ctx, network, address)
}

// resolveHost resolves the IP address of a host using DNS and caching mechanisms.
func (d *dialer) resolveHost(ctx context.Context, host string) (net.IPAddr, error) {
	ip, exist := d.getIPFromCache(ctx, host)
	if exist {
		return ip, nil
	}

	d.chanLock.Lock()

	ch := d.resolveChannels.Get(host)
	if ch == nil {
		ch = make(chan error, 1)
		d.resolveChannels.Set(host, ch)

		go d.resolveAndCache(ctx, host, ch)
	}

	d.chanLock.Unlock()

	select {
	case err := <-ch:
		ch <- err

		if err != nil {
			return net.IPAddr{}, err
		}

		ip, _ := d.getIPFromCache(ctx, host)

		return ip, nil
	case <-ctx.Done():
		return net.IPAddr{}, ctx.Err()
	}
}

// resolveAndCache resolves the IP address of a host using DNS and caches the result.
func (d *dialer) resolveAndCache(ctx context.Context, host string, ch chan<- error) {
	atomic.AddInt64(&d.stats.dnsQuery, 1)

	var (
		item            *cacheItem
		noDNSRecordsErr = fmt.Errorf("no dns records for host %s", host)
	)

	defer func() {
		if item != nil {
			atomic.AddInt64(&d.stats.successfulDNSQuery, 1)
		}

		d.lock.Lock()
		defer d.lock.Unlock()

		if item == nil {
			d.cache.Delete(host)
		} else {
			d.cache.Set(host, item)
		}

		d.chanLock.Lock()
		defer d.chanLock.Unlock()

		d.resolveChannels.Delete(host)
	}()

	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		ch <- noDNSRecordsErr
		return
	}

	var convertedIPs []net.IPAddr

	for _, ip := range ips {
		if ip4 := ip.IP.To4(); ip4 != nil {
			convertedIPs = append(convertedIPs, net.IPAddr{IP: ip4})
		}
	}

	if len(convertedIPs) == 0 {
		ch <- noDNSRecordsErr
		return
	}

	item = newCacheItem(host, convertedIPs, d.cacheDuration, d.forceRefreshTimes)
	ch <- nil
}

// getIPFromCache retrieves the IP address from the cache for a given host.
// Returns the IP address and a boolean indicating whether the IP is valid and present in the cache.
func (d *dialer) getIPFromCache(_ context.Context, host string) (net.IPAddr, bool) {
	d.lock.RLock()
	item := d.cache.Get(host)
	d.lock.RUnlock()

	if item == nil {
		return net.IPAddr{}, false
	}

	ip, valid := item.ip()
	if !valid {
		d.invalidateCache(host)
	}

	return ip, valid
}

// invalidateCache removes the cached entry for the specified host from the cache.
func (d *dialer) invalidateCache(host string) {
	d.lock.Lock()
	d.cache.Delete(host)
	d.lock.Unlock()
}
