package surf

import (
	"encoding/base64"
	"slices"
	"strings"
)

var knownClientHintNames = []string{
	"device-memory",
	"sec-ch-device-memory",
	"dpr",
	"sec-ch-dpr",
	"viewport-width",
	"sec-ch-viewport-width",
	"sec-ch-viewport-height",
	"width",
	"sec-ch-width",
	"rtt",
	"downlink",
	"ect",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-full-version",
	"sec-ch-ua-arch",
	"sec-ch-ua-platform",
	"sec-ch-ua-platform-version",
	"sec-ch-ua-model",
	"sec-ch-ua-bitness",
	"sec-ch-ua-wow64",
	"sec-ch-ua-full-version-list",
	"sec-ch-ua-form-factors",
	"sec-ch-prefers-color-scheme",
	"sec-ch-prefers-reduced-motion",
	"sec-ch-prefers-reduced-transparency",
	"save-data",
}

func knownClientHint(s string) bool { return slices.Contains(knownClientHintNames, s) }

func defaultClientHint(s string) bool {
	return s == "sec-ch-ua" || s == "sec-ch-ua-mobile" || s == "sec-ch-ua-platform" || s == "save-data"
}

func clientHintAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func clientHintDigit(c byte) bool { return c >= '0' && c <= '9' }

func clientHintTokenChar(c byte) bool {
	return clientHintAlpha(c) || clientHintDigit(c) || strings.ContainsRune("!#$%&'*+-.^_`|~:/", rune(c))
}

// parseClientHints validates an RFC 8941 token list used by Accept-CH and Critical-CH.
// Parameters are accepted and validated. Unknown tokens are ignored; a malformed
// member rejects the entire list. An empty valid list is distinguishable from
// invalid input and clears previously remembered hints.
// https://github.com/chromium/chromium/blob/158.0.8127.18/services/network/public/cpp/client_hints.cc
func parseClientHints(value string) ([]string, bool) {
	if len(value) > 64<<10 {
		return nil, false
	}

	p := clientHintParser{s: value}
	p.ows()

	result := []string{}
	seen := make(map[string]bool)

	for p.i < len(p.s) {
		name, ok := p.token()
		if !ok || !p.parameters() {
			return nil, false
		}

		name = strings.ToLower(name)
		if knownClientHint(name) && !seen[name] {
			result = append(result, name)
			seen[name] = true
		}

		p.ows()
		if p.i == len(p.s) {
			return result, true
		}

		if p.s[p.i] != ',' {
			return nil, false
		}

		p.i++
		p.ows()

		if p.i == len(p.s) {
			return nil, false
		}
	}

	return result, true
}

type clientHintParser struct {
	s string
	i int
}

func (p *clientHintParser) ows() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *clientHintParser) token() (string, bool) {
	start := p.i
	if p.i == len(p.s) || !clientHintAlpha(p.s[p.i]) && p.s[p.i] != '*' {
		return "", false
	}

	p.i++
	for p.i < len(p.s) && clientHintTokenChar(p.s[p.i]) {
		p.i++
	}

	return p.s[start:p.i], true
}

func (p *clientHintParser) parameters() bool {
	for p.i < len(p.s) && p.s[p.i] == ';' {
		p.i++
		for p.i < len(p.s) && p.s[p.i] == ' ' {
			p.i++
		}

		if p.i == len(p.s) || !(p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] == '*') {
			return false
		}

		p.i++
		for p.i < len(p.s) && (p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || clientHintDigit(p.s[p.i]) || strings.ContainsRune("_.*-", rune(p.s[p.i]))) {
			p.i++
		}

		if p.i < len(p.s) && p.s[p.i] == '=' {
			p.i++
			if !p.item() {
				return false
			}
		}
	}

	return true
}

func (p *clientHintParser) item() bool {
	if p.i == len(p.s) {
		return false
	}

	switch p.s[p.i] {
	case '"':
		p.i++
		for p.i < len(p.s) {
			c := p.s[p.i]
			p.i++
			if c == '"' {
				return true
			}
			if c == '\\' {
				if p.i == len(p.s) || p.s[p.i] != '"' && p.s[p.i] != '\\' {
					return false
				}
				p.i++
			} else if c < 0x20 || c > 0x7e {
				return false
			}
		}
		return false
	case '?':
		p.i++
		if p.i == len(p.s) || p.s[p.i] != '0' && p.s[p.i] != '1' {
			return false
		}
		p.i++
		return true
	case ':':
		p.i++
		start := p.i
		for p.i < len(p.s) && p.s[p.i] != ':' {
			p.i++
		}
		if p.i == len(p.s) {
			return false
		}
		_, err := base64.StdEncoding.DecodeString(p.s[start:p.i])
		p.i++
		return err == nil
	}

	if p.s[p.i] == '-' || clientHintDigit(p.s[p.i]) {
		if p.s[p.i] == '-' {
			p.i++
		}

		start := p.i
		for p.i < len(p.s) && clientHintDigit(p.s[p.i]) {
			p.i++
		}

		n := p.i - start
		if n == 0 || n > 15 {
			return false
		}

		if p.i < len(p.s) && p.s[p.i] == '.' {
			if n > 12 {
				return false
			}

			p.i++
			start = p.i

			for p.i < len(p.s) && clientHintDigit(p.s[p.i]) {
				p.i++
			}

			return p.i-start >= 1 && p.i-start <= 3
		}

		return true
	}

	_, ok := p.token()

	return ok
}
