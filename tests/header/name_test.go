package header_test

import (
	"strings"
	"testing"

	"github.com/enetx/surf/header"
)

func TestHeaderConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"ACCEPT", header.ACCEPT, "accept"},
		{"ACCEPT_CHARSET", header.ACCEPT_CHARSET, "accept-charset"},
		{"ACCEPT_ENCODING", header.ACCEPT_ENCODING, "accept-encoding"},
		{"ACCEPT_LANGUAGE", header.ACCEPT_LANGUAGE, "accept-language"},
		{"ACCEPT_RANGES", header.ACCEPT_RANGES, "accept-ranges"},
		{"ACCESS_CONTROL_ALLOW_CREDENTIALS", header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "access-control-allow-credentials"},
		{"ACCESS_CONTROL_ALLOW_HEADERS", header.ACCESS_CONTROL_ALLOW_HEADERS, "access-control-allow-headers"},
		{"ACCESS_CONTROL_ALLOW_METHODS", header.ACCESS_CONTROL_ALLOW_METHODS, "access-control-allow-methods"},
		{"ACCESS_CONTROL_ALLOW_ORIGIN", header.ACCESS_CONTROL_ALLOW_ORIGIN, "access-control-allow-origin"},
		{"ACCESS_CONTROL_EXPOSE_HEADERS", header.ACCESS_CONTROL_EXPOSE_HEADERS, "access-control-expose-headers"},
		{"ACCESS_CONTROL_MAX_AGE", header.ACCESS_CONTROL_MAX_AGE, "access-control-max-age"},
		{"ACCESS_CONTROL_REQUEST_HEADERS", header.ACCESS_CONTROL_REQUEST_HEADERS, "access-control-request-headers"},
		{"ACCESS_CONTROL_REQUEST_METHOD", header.ACCESS_CONTROL_REQUEST_METHOD, "access-control-request-method"},
		{"AGE", header.AGE, "age"},
		{"ALLOW", header.ALLOW, "allow"},
		{"ALT_SVC", header.ALT_SVC, "alt-svc"},
		{"AUTHORIZATION", header.AUTHORIZATION, "authorization"},
		{"CACHE_CONTROL", header.CACHE_CONTROL, "cache-control"},
		{"CACHE_STATUS", header.CACHE_STATUS, "cache-status"},
		{"CDN_CACHE_CONTROL", header.CDN_CACHE_CONTROL, "cdn-cache-control"},
		{"CONNECTION", header.CONNECTION, "connection"},
		{"CONTENT_DISPOSITION", header.CONTENT_DISPOSITION, "content-disposition"},
		{"CONTENT_ENCODING", header.CONTENT_ENCODING, "content-encoding"},
		{"CONTENT_LANGUAGE", header.CONTENT_LANGUAGE, "content-language"},
		{"CONTENT_LENGTH", header.CONTENT_LENGTH, "content-length"},
		{"CONTENT_LOCATION", header.CONTENT_LOCATION, "content-location"},
		{"CONTENT_RANGE", header.CONTENT_RANGE, "content-range"},
		{"CONTENT_SECURITY_POLICY", header.CONTENT_SECURITY_POLICY, "content-security-policy"},
		{"CONTENT_SECURITY_POLICY_REPORT_ONLY", header.CONTENT_SECURITY_POLICY_REPORT_ONLY, "content-security-policy-report-only"},
		{"CONTENT_TYPE", header.CONTENT_TYPE, "content-type"},
		{"COOKIE", header.COOKIE, "cookie"},
		{"DNT", header.DNT, "dnt"},
		{"DATE", header.DATE, "date"},
		{"ETAG", header.ETAG, "etag"},
		{"EXPECT", header.EXPECT, "expect"},
		{"EXPIRES", header.EXPIRES, "expires"},
		{"FORWARDED", header.FORWARDED, "forwarded"},
		{"FROM", header.FROM, "from"},
		{"HOST", header.HOST, "host"},
		{"IF_MATCH", header.IF_MATCH, "if-match"},
		{"IF_MODIFIED_SINCE", header.IF_MODIFIED_SINCE, "if-modified-since"},
		{"IF_NONE_MATCH", header.IF_NONE_MATCH, "if-none-match"},
		{"IF_RANGE", header.IF_RANGE, "if-range"},
		{"IF_UNMODIFIED_SINCE", header.IF_UNMODIFIED_SINCE, "if-unmodified-since"},
		{"LAST_MODIFIED", header.LAST_MODIFIED, "last-modified"},
		{"LINK", header.LINK, "link"},
		{"LOCATION", header.LOCATION, "location"},
		{"MAX_FORWARDS", header.MAX_FORWARDS, "max-forwards"},
		{"ORIGIN", header.ORIGIN, "origin"},
		{"PRAGMA", header.PRAGMA, "pragma"},
		{"PRIORITY", header.PRIORITY, "priority"},
		{"PROXY_AUTHENTICATE", header.PROXY_AUTHENTICATE, "proxy-authenticate"},
		{"PROXY_AUTHORIZATION", header.PROXY_AUTHORIZATION, "proxy-authorization"},
		{"PUBLIC_KEY_PINS", header.PUBLIC_KEY_PINS, "public-key-pins"},
		{"PUBLIC_KEY_PINS_REPORT_ONLY", header.PUBLIC_KEY_PINS_REPORT_ONLY, "public-key-pins-report-only"},
		{"RANGE", header.RANGE, "range"},
		{"REFERER", header.REFERER, "referer"},
		{"REFERRER_POLICY", header.REFERRER_POLICY, "referrer-policy"},
		{"REFRESH", header.REFRESH, "refresh"},
		{"RETRY_AFTER", header.RETRY_AFTER, "retry-after"},
		{"SEC_CH_UA", header.SEC_CH_UA, "sec-ch-ua"},
		{"SEC_CH_UA_MOBILE", header.SEC_CH_UA_MOBILE, "sec-ch-ua-mobile"},
		{"SEC_CH_UA_PLATFORM", header.SEC_CH_UA_PLATFORM, "sec-ch-ua-platform"},
		{"SEC_FETCH_SITE", header.SEC_FETCH_SITE, "sec-fetch-site"},
		{"SEC_FETCH_MODE", header.SEC_FETCH_MODE, "sec-fetch-mode"},
		{"SEC_FETCH_USER", header.SEC_FETCH_USER, "sec-fetch-user"},
		{"SEC_FETCH_DEST", header.SEC_FETCH_DEST, "sec-fetch-dest"},
		{"SEC_WEBSOCKET_ACCEPT", header.SEC_WEBSOCKET_ACCEPT, "sec-websocket-accept"},
		{"SEC_WEBSOCKET_EXTENSIONS", header.SEC_WEBSOCKET_EXTENSIONS, "sec-websocket-extensions"},
		{"SEC_WEBSOCKET_KEY", header.SEC_WEBSOCKET_KEY, "sec-websocket-key"},
		{"SEC_WEBSOCKET_PROTOCOL", header.SEC_WEBSOCKET_PROTOCOL, "sec-websocket-protocol"},
		{"SEC_WEBSOCKET_VERSION", header.SEC_WEBSOCKET_VERSION, "sec-websocket-version"},
		{"SERVER", header.SERVER, "server"},
		{"SET_COOKIE", header.SET_COOKIE, "set-cookie"},
		{"STRICT_TRANSPORT_SECURITY", header.STRICT_TRANSPORT_SECURITY, "strict-transport-security"},
		{"TE", header.TE, "te"},
		{"TRAILER", header.TRAILER, "trailer"},
		{"TRANSFER_ENCODING", header.TRANSFER_ENCODING, "transfer-encoding"},
		{"USER_AGENT", header.USER_AGENT, "user-agent"},
		{"UPGRADE", header.UPGRADE, "upgrade"},
		{"UPGRADE_INSECURE_REQUESTS", header.UPGRADE_INSECURE_REQUESTS, "upgrade-insecure-requests"},
		{"VARY", header.VARY, "vary"},
		{"VIA", header.VIA, "via"},
		{"WARNING", header.WARNING, "warning"},
		{"WWW_AUTHENTICATE", header.WWW_AUTHENTICATE, "www-authenticate"},
		{"X_CONTENT_TYPE_OPTIONS", header.X_CONTENT_TYPE_OPTIONS, "x-content-type-options"},
		{"X_DNS_PREFETCH_CONTROL", header.X_DNS_PREFETCH_CONTROL, "x-dns-prefetch-control"},
		{"X_FRAME_OPTIONS", header.X_FRAME_OPTIONS, "x-frame-options"},
		{"X_XSS_PROTECTION", header.X_XSS_PROTECTION, "x-xss-protection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("expected %s to be %q, got %q", tt.name, tt.expected, tt.constant)
			}
		})
	}
}

func TestHeaderConstantsNotEmpty(t *testing.T) {
	t.Parallel()

	constants := []struct {
		name  string
		value string
	}{
		{"ACCEPT", header.ACCEPT},
		{"CONTENT_TYPE", header.CONTENT_TYPE},
		{"USER_AGENT", header.USER_AGENT},
		{"AUTHORIZATION", header.AUTHORIZATION},
		{"CACHE_CONTROL", header.CACHE_CONTROL},
		{"CONNECTION", header.CONNECTION},
		{"HOST", header.HOST},
		{"LOCATION", header.LOCATION},
		{"ORIGIN", header.ORIGIN},
		{"REFERER", header.REFERER},
		{"SERVER", header.SERVER},
		{"SET_COOKIE", header.SET_COOKIE},
		{"COOKIE", header.COOKIE},
	}

	for _, c := range constants {
		t.Run(c.name, func(t *testing.T) {
			if c.value == "" {
				t.Errorf("expected %s constant to not be empty", c.name)
			}
		})
	}
}

func TestHeaderConstantsFormat(t *testing.T) {
	t.Parallel()

	// Test that all header constants are lowercase
	constants := []struct {
		name  string
		value string
	}{
		{"CONTENT_TYPE", header.CONTENT_TYPE},
		{"USER_AGENT", header.USER_AGENT},
		{"ACCEPT_ENCODING", header.ACCEPT_ENCODING},
		{"CACHE_CONTROL", header.CACHE_CONTROL},
		{"WWW_AUTHENTICATE", header.WWW_AUTHENTICATE},
	}

	for _, c := range constants {
		t.Run(c.name, func(t *testing.T) {
			if c.value != strings.ToLower(c.value) {
				t.Errorf("expected %s to be lowercase, got %q", c.name, c.value)
			}

			// Check that multi-word headers use hyphens
			if strings.Contains(c.name, "_") && !strings.Contains(c.value, "-") {
				t.Errorf("expected %s to contain hyphens for multi-word header, got %q", c.name, c.value)
			}
		})
	}
}
