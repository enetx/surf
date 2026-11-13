package surf

import (
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/enetx/http"
)

// ClientHintBrand describes one brand in Sec-CH-UA-Full-Version-List.
type ClientHintBrand struct {
	// Brand is the product name or GREASE brand.
	Brand string
	// Version is the complete version advertised for this brand.
	Version string
}

// clientHintsConfig configures a snapshot of available hints and origin cache policy.
// Surf exposes it through Builder.ClientHints(); profiles use the same setters.
type clientHintsConfig struct {
	enabled     bool
	capacity    int
	lifetime    time.Duration
	clock       func() time.Time
	values      map[string]string
	fullVersion string
	brands      []ClientHintBrand
	err         error
}

// newClientHintsConfig creates enabled negotiation with a 1024-origin in-memory bound.
// Browser identities and hardware values come from the selected profile.
func newClientHintsConfig() *clientHintsConfig {
	return &clientHintsConfig{enabled: true, capacity: 1024, clock: time.Now, values: make(map[string]string)}
}

// Enabled controls automatic hint emission, learning and critical restarts.
func (b *clientHintsConfig) Enabled(value bool) *clientHintsConfig { b.enabled = value; return b }

// Capacity bounds remembered origins. Valid values are 1..1048576.
func (b *clientHintsConfig) Capacity(value int) *clientHintsConfig { b.capacity = value; return b }

// Lifetime expires remembered hints after this duration. Zero retains them for
// the client lifetime. This is an application cache bound, not a wire lifetime.
func (b *clientHintsConfig) Lifetime(value time.Duration) *clientHintsConfig {
	b.lifetime = value
	return b
}

// Clock supplies cache time. Nil selects time.Now.
func (b *clientHintsConfig) Clock(value func() time.Time) *clientHintsConfig {
	b.clock = value
	return b
}

// Value supplies a serialized value for a recognized hint, such as
// sec-ch-device-memory or sec-ch-prefers-color-scheme. Request headers take
// precedence. A value is sent only when enabled for that origin, except for
// Chromium's default low-entropy hints. Unknown hint names fail Build.
func (b *clientHintsConfig) Value(name, value string) *clientHintsConfig {
	name = strings.ToLower(name)
	if !knownClientHint(name) || !validClientHintValue(value) {
		b.err = fmt.Errorf("client hints: invalid hint %q or header value", name)
		return b
	}

	b.values[name] = value
	if name == "sec-ch-ua-full-version-list" {
		b.brands = nil
	}

	return b
}

func (b *clientHintsConfig) stringValue(name, value string) *clientHintsConfig {
	quoted, err := quoteClientHint(value)
	if err != nil {
		b.err = fmt.Errorf("client hints: %s: %w", name, err)
		return b
	}

	return b.Value(name, quoted)
}

// Architecture sets sec-ch-ua-arch, such as x86, arm or an empty Android value.
func (b *clientHintsConfig) Architecture(value string) *clientHintsConfig {
	return b.stringValue("sec-ch-ua-arch", value)
}

// Bitness sets sec-ch-ua-bitness, such as 64, 32 or an empty Android value.
func (b *clientHintsConfig) Bitness(value string) *clientHintsConfig {
	return b.stringValue("sec-ch-ua-bitness", value)
}

// PlatformVersion sets the target OS version rather than the host Go runtime's OS.
func (b *clientHintsConfig) PlatformVersion(value string) *clientHintsConfig {
	return b.stringValue("sec-ch-ua-platform-version", value)
}

// Model sets the target device model. Desktop browsers normally advertise empty.
func (b *clientHintsConfig) Model(value string) *clientHintsConfig {
	return b.stringValue("sec-ch-ua-model", value)
}

// FullVersion sets sec-ch-ua-full-version and updates full-version-list entries
// that used the previous browser version. GREASE versions remain independent.
func (b *clientHintsConfig) FullVersion(value string) *clientHintsConfig {
	for i := range b.brands {
		if b.fullVersion != "" && b.brands[i].Version == b.fullVersion {
			b.brands[i].Version = value
		}
	}

	b.fullVersion = value

	return b.stringValue("sec-ch-ua-full-version", value)
}

// FullVersionList sets the complete ordered product and GREASE brand list.
// The input slice is copied; later FullVersion calls update matching entries.
func (b *clientHintsConfig) FullVersionList(value ...ClientHintBrand) *clientHintsConfig {
	b.brands = append([]ClientHintBrand{}, value...)
	return b
}

// WoW64 reports whether the selected Chrome process is 32-bit on 64-bit Windows.
func (b *clientHintsConfig) WoW64(value bool) *clientHintsConfig {
	if value {
		return b.Value("sec-ch-ua-wow64", "?1")
	}
	return b.Value("sec-ch-ua-wow64", "?0")
}

// FormFactors sets the ordered form-factor strings, such as Desktop or Mobile.
func (b *clientHintsConfig) FormFactors(values ...string) *clientHintsConfig {
	var parts []string
	for _, value := range values {
		quoted, err := quoteClientHint(value)
		if err != nil {
			b.err = err
			return b
		}

		parts = append(parts, quoted)
	}

	return b.Value("sec-ch-ua-form-factors", strings.Join(parts, ", "))
}

// Build validates settings and creates a transport with independent origin state.
// Base is the existing protocol transport and must be non-nil.
func (b *clientHintsConfig) build(base http.RoundTripper) (*clientHintsTransport, error) {
	if b.err != nil {
		return nil, b.err
	}

	if base == nil || b.capacity < 1 || b.capacity > 1<<20 || b.lifetime < 0 {
		return nil, fmt.Errorf("client hints: invalid transport, capacity or lifetime")
	}

	values := make(map[string]string, len(b.values)+1)
	maps.Copy(values, b.values)

	if b.brands != nil {
		var parts []string
		for _, entry := range b.brands {
			brand, err := quoteClientHint(entry.Brand)
			if err != nil {
				return nil, err
			}

			version, err := quoteClientHint(entry.Version)
			if err != nil {
				return nil, err
			}

			parts = append(parts, brand+";v="+version)
		}

		values["sec-ch-ua-full-version-list"] = strings.Join(parts, ", ")
	}

	clock := b.clock
	if clock == nil {
		clock = time.Now
	}

	return &clientHintsTransport{
		Base:    base,
		enabled: b.enabled,
		values:  values,
		cache:   newClientHintStore(b.capacity, b.lifetime, clock),
	}, nil
}

func validClientHintValue(s string) bool {
	for _, c := range s {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}

	return true
}

func quoteClientHint(value string) (string, error) {
	for _, c := range value {
		if c < 0x20 || c > 0x7e {
			return "", fmt.Errorf("client hints: value requires printable ASCII")
		}
	}

	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`, nil
}
