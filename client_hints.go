package surf

import (
	"slices"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
)

// ClientHints is Surf's fluent configuration for available Client Hints and
// origin opt-ins. Chrome desktop/Android enable negotiation automatically.
// Other clients can enable it with Set. Explicit request headers take precedence.
type ClientHints struct {
	builder    *Builder
	overrides  []func(*clientHintsConfig)
	configured bool
}

// ClientHints opens the client-hint sub-builder. Browser defaults are applied
// first and explicit settings last, independent of configuration call order.
func (b *Builder) ClientHints() *ClientHints {
	if b.clientHints == nil {
		b.clientHints = &ClientHints{builder: b}
	}
	return b.clientHints
}

func (h *ClientHints) configure(fn func(*clientHintsConfig)) *ClientHints {
	h.configured = true
	h.overrides = append(h.overrides, fn)
	return h
}

// Enabled controls negotiation and emission of learned hints. Explicit request
// headers, including the profile's static low-entropy fields, remain caller-owned.
func (h *ClientHints) Enabled(value bool) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Enabled(value) })
}

// Capacity bounds remembered origins to 1..1048576; the default is 1024.
func (h *ClientHints) Capacity(value int) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Capacity(value) })
}

// Lifetime bounds opt-in retention. Zero keeps in-memory state for this client.
func (h *ClientHints) Lifetime(value time.Duration) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Lifetime(value) })
}

// Clock supplies origin-cache time and must support concurrent calls. Nil restores time.Now.
func (h *ClientHints) Clock(value func() time.Time) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Clock(value) })
}

// Value supplies a serialized recognized hint value, emitted only when opted in
// unless Chromium sends that hint by default. Unknown names fail Builder.Build.
func (h *ClientHints) Value(name, value string) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Value(name, value) })
}

// Architecture sets sec-ch-ua-arch, such as x86 or arm; Android normally uses empty.
func (h *ClientHints) Architecture(value string) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Architecture(value) })
}

// Bitness sets sec-ch-ua-bitness, such as 64 or 32; Android normally uses empty.
func (h *ClientHints) Bitness(value string) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Bitness(value) })
}

// PlatformVersion sets the target OS version, independent of the Go host OS.
func (h *ClientHints) PlatformVersion(value string) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.PlatformVersion(value) })
}

// Model sets the device model; desktop Chrome uses an empty model.
func (h *ClientHints) Model(value string) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.Model(value) })
}

// FullVersion sets the complete browser version and updates matching product
// entries in its full-version list, leaving the GREASE version independent.
func (h *ClientHints) FullVersion(value string) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.FullVersion(value) })
}

// FullVersionList supplies ordered complete product and GREASE versions.
func (h *ClientHints) FullVersionList(values ...ClientHintBrand) *ClientHints {
	copy := slices.Clone(values)
	return h.configure(func(c *clientHintsConfig) { c.FullVersionList(copy...) })
}

// WoW64 reports a 32-bit Chrome process running on 64-bit Windows.
func (h *ClientHints) WoW64(value bool) *ClientHints {
	return h.configure(func(c *clientHintsConfig) { c.WoW64(value) })
}

// FormFactors supplies ordered form-factor strings, such as Desktop or Mobile.
func (h *ClientHints) FormFactors(values ...string) *ClientHints {
	copy := slices.Clone(values)
	return h.configure(func(c *clientHintsConfig) { c.FormFactors(copy...) })
}

// Set applies the accumulated configuration and returns the ordinary client builder.
// Invalid names, values or limits are reported by Builder.Build.
func (h *ClientHints) Set() *Builder { h.configured = true; return h.builder }

func (b *Builder) applyClientHints() error {
	base := b.cli.cli.Transport
	if old, ok := base.(*clientHintsTransport); ok {
		base = old.Base
		b.cli.cli.Transport = base
	}

	if b.clientHintValues == nil && (b.clientHints == nil || !b.clientHints.configured) {
		return nil
	}

	config := newClientHintsConfig()

	if b.clientHintValues != nil {
		values := b.clientHintValues(b.clientHintOS)
		values.Iter().ForEach(func(name, value string) { config.Value(name, value) })
		// Retain the product version for FullVersion overrides applied after profile data.
		config.fullVersion = unquoteClientHint(config.values["sec-ch-ua-full-version"])
		config.brands = parseClientHintBrands(config.values["sec-ch-ua-full-version-list"])
	}

	if b.clientHints != nil {
		for _, configure := range b.clientHints.overrides {
			configure(config)
		}
	}

	transport, err := config.build(base)
	if err != nil {
		return err
	}

	transport.Jar = func() http.CookieJar { return b.cli.cli.Jar }

	profile := b.headerProfile
	if profile != nil {
		transport.Prepare = func(req *http.Request, _ bool) { *req = *profile.logical(req) }
	}

	b.cli.cli.Transport = transport

	return nil
}

// ClearClientHints clears learned origin opt-ins without closing connections or
// changing configured metadata. It is safe alongside concurrent requests.
func (c *Client) ClearClientHints() {
	if transport, ok := c.cli.Transport.(*clientHintsTransport); ok {
		transport.Clear()
	}
}

// ClientHintNames returns a copy of the remembered opt-in names for a URL's
// origin. It reports no opt-ins when negotiation is not installed.
func (c *Client) ClientHintNames(rawURL g.String) []string {
	if transport, ok := c.cli.Transport.(*clientHintsTransport); ok {
		return transport.Hints(rawURL.Std())
	}
	return nil
}

// These fields are already Structured Field strings validated with the profile.
func unquoteClientHint(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return ""
}

func parseClientHintBrands(value string) []ClientHintBrand {
	// Profile values use the canonical quoted brand/version representation.
	// FullVersionList's typed setter handles application-supplied custom brands.
	var brands []ClientHintBrand
	for _, item := range splitClientHintBrands(value) {
		brands = append(brands, ClientHintBrand{Brand: item[0], Version: item[1]})
	}

	return brands
}

func splitClientHintBrands(value string) [][2]string {
	var result [][2]string
	read := func(s string) (string, string, bool) {
		s = strings.TrimSpace(s)
		if len(s) == 0 || s[0] != '"' {
			return "", "", false
		}

		var out strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			if c == '"' {
				return out.String(), s[i+1:], true
			}

			if c == '\\' {
				i++
				if i == len(s) || s[i] != '\\' && s[i] != '"' {
					return "", "", false
				}
				c = s[i]
			} else if c < 0x20 || c > 0x7e {
				return "", "", false
			}

			out.WriteByte(c)
		}

		return "", "", false
	}

	for strings.TrimSpace(value) != "" {
		brand, tail, ok := read(value)
		if !ok {
			return nil
		}

		tail = strings.TrimSpace(tail)
		if !strings.HasPrefix(tail, ";v=") {
			return nil
		}

		version, tail, ok := read(tail[3:])
		if !ok {
			return nil
		}

		result = append(result, [2]string{brand, version})
		tail = strings.TrimSpace(tail)
		if tail == "" {
			return result
		}

		if tail[0] != ',' {
			return nil
		}

		value = tail[1:]
		if strings.TrimSpace(value) == "" {
			return nil
		}
	}

	return result
}
