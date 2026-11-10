package surf

import (
	"github.com/enetx/g"
	"github.com/enetx/g/rand"
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
	im.os = rand.Choice(g.SliceOf(profiles.Windows, profiles.MacOS, profiles.Linux, profiles.Android, profiles.IOS)).
		Some()
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

// Chrome impersonates Chrome 156 on desktop/Android and the captured Chrome 157 on iOS.
func (im *Impersonate) Chrome() *Builder {
	v := chrome.Desktop
	switch im.os {
	case profiles.Android:
		v = chrome.Mobile
	case profiles.IOS:
		v = chrome.IOS
	}

	return im.applyVariant(v)
}

// Firefox impersonates Firefox 159 on desktop and the existing mobile profiles.
func (im *Impersonate) Firefox() *Builder {
	v := firefox.Desktop
	switch im.os {
	case profiles.Android:
		v = firefox.Mobile
	case profiles.IOS:
		v = firefox.IOS
	}

	return im.applyVariant(v)
}

// applyVariant materialises a browser and form-factor profile onto the Builder. Profile packages
// own all data (TLS spec, boundary, H2/H3 SETTINGS, header set), this method owns sequencing.
func (im *Impersonate) applyVariant(v profiles.Variant) *Builder {
	im.builder.headersApplier = v.Headers

	im.builder.Boundary(v.Boundary)

	if v.HelloSpec != nil {
		ja := im.builder.JA()
		ja.shuffle = v.ShuffleExtensions
		ja.SetHelloSpec(*v.HelloSpec)
	} else {
		im.builder.JA().SetHelloID(v.HelloID)
	}

	h2 := im.builder.HTTP2Settings()
	*h2 = HTTP2Settings{builder: h2.builder, registered: h2.registered}

	v.ConfigureH2(h2adapter{h2})
	h2.Set()

	h3 := im.builder.HTTP3Settings()
	// Replacing a browser profile discards its previous H3 settings while keeping
	// the one registered transport factory. Later user overrides still merge.
	*h3 = HTTP3Settings{builder: h3.builder, registered: h3.registered}

	v.ConfigureH3(h3adapter{h3})
	if v.ConfigureQPACK != nil {
		v.ConfigureQPACK(h3adapter{h3})
	}
	if v.ConfigureRequestBody != nil {
		v.ConfigureRequestBody(h3adapter{h3})
	}
	// Apply QUIC after ordered H3 SETTINGS: EnableDatagrams updates the existing
	// H3_DATAGRAM entry without changing the profile's SETTINGS order.
	if v.ConfigureQUIC != nil {
		v.ConfigureQUIC(quicadapter{im.builder.QUICSettings()})
	}

	h3.Set()

	return im.builder.SetHeaders(*v.BuildHeaders(im.os))
}
