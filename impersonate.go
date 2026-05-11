package surf

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"
)

type Impersonate struct {
	builder *Builder
	os      profiles.OSKey
}

// RandomOS selects a random OS (Windows, macOS, Linux, Android, or iOS) for the impersonate.
func (im *Impersonate) RandomOS() *Impersonate {
	im.os = g.SliceOf(profiles.Windows, profiles.MacOS, profiles.Linux, profiles.Android, profiles.IOS).Random()
	return im
}

// Windows sets the OS to Windows.
func (im *Impersonate) Windows() *Impersonate {
	im.os = profiles.Windows
	return im
}

// MacOS sets the OS to macOS.
func (im *Impersonate) MacOS() *Impersonate {
	im.os = profiles.MacOS
	return im
}

// Linux sets the OS to Linux.
func (im *Impersonate) Linux() *Impersonate {
	im.os = profiles.Linux
	return im
}

// Android sets the OS to Android.
func (im *Impersonate) Android() *Impersonate {
	im.os = profiles.Android
	return im
}

// IOS sets the OS to iOS.
func (im *Impersonate) IOS() *Impersonate {
	im.os = profiles.IOS
	return im
}

// Chrome impersonates Chrome browser v145.
func (im *Impersonate) Chrome() *Builder {
	v := chrome.Desktop
	if im.os.IsMobile() {
		v = chrome.Mobile
	}

	return im.applyVariant(v)
}

// Firefox impersonates Firefox browser v148.
func (im *Impersonate) Firefox() *Builder {
	v := firefox.Desktop
	if im.os.IsMobile() {
		v = firefox.Mobile
	}

	return im.applyVariant(v)
}

// applyVariant materialises a browser and form-factor profile onto the Builder. Profile packages
// own all data (TLS spec, boundary, H2/H3 SETTINGS, header set), this method owns sequencing.
func (im *Impersonate) applyVariant(v profiles.Variant) *Builder {
	im.builder.headersApplier = v.Headers

	im.builder.Boundary(v.Boundary)

	if v.HelloSpec != nil {
		im.builder.JA().SetHelloSpec(*v.HelloSpec)
	} else {
		im.builder.JA().SetHelloID(v.HelloID)
	}

	h2 := im.builder.HTTP2Settings()
	v.ConfigureH2(h2adapter{h2})
	h2.Set()

	h3 := im.builder.HTTP3Settings()
	v.ConfigureH3(h3adapter{h3})
	h3.Set()

	return im.builder.SetHeaders(*v.BuildHeaders(im.os))
}
