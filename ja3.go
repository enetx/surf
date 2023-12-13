package surf

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf/internal/connectproxy"
)

// https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html
type ja3 struct {
	spec utls.ClientHelloSpec
	id   utls.ClientHelloID
	opt  *Options
	str  string
}

// SetHelloStr sets a custom JA3 string for the TLS connection.
//
// This method allows you to set a custom JA3 string to be used during the TLS handshake.
// The provided string should be a valid JA3 string.
//
// It returns a pointer to the Options struct for method chaining. This allows
// additional configuration methods to be called on the result.
//
// Example usage:
//
//	JA3.SetHelloStr("customJA3")
func (j *ja3) SetHelloStr(str string) *Options {
	j.str = str
	return j.setOptions()
}

// SetHelloID sets a ClientHelloID for the TLS connection.
//
// The provided ClientHelloID is used to customize the TLS handshake. This
// should be a valid identifier that can be mapped to a specific ClientHelloSpec.
//
// It returns a pointer to the Options struct for method chaining. This allows
// additional configuration methods to be called on the result.
//
// Example usage:
//
//	JA3.SetHelloID(utls.HelloChrome_Auto)
func (j *ja3) SetHelloID(id utls.ClientHelloID) *Options {
	j.id = id
	return j.setOptions()
}

// SetHelloSpec sets a custom ClientHelloSpec for the TLS connection.
//
// This method allows you to set a custom ClientHelloSpec to be used during the TLS handshake.
// The provided spec should be a valid ClientHelloSpec.
//
// It returns a pointer to the Options struct for method chaining. This allows
// additional configuration methods to be called on the result.
//
// Example usage:
//
//	JA3.SetHelloSpec(spec)
func (j *ja3) SetHelloSpec(spec utls.ClientHelloSpec) *Options {
	j.spec = spec
	return j.setOptions()
}

func (j *ja3) setOptions() *Options {
	return j.opt.addcliMW(func(c *Client) {
		if !j.opt.useSingleton {
			j.opt.addrespMW(clearCachedTransportsMW)
		}

		if j.opt.proxy != nil {
			var tp string
			switch p := j.opt.proxy.(type) {
			case string:
				tp = p
			case []string:
				tp = p[rand.Intn(len(p))]
			}

			if dialer, err := connectproxy.NewDialer(tp); err != nil {
				c.GetTransport().(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, err }
			} else {
				c.GetTransport().(*http.Transport).DialContext = dialer.DialContext
			}
		}

		c.GetClient().Transport = newRoundTripper(j, c.GetTransport())
	})
}

// getSpec determines the ClientHelloSpec to be used for the TLS connection.
//
// The ClientHelloSpec is selected based on the following order of precedence:
// 1. If a custom JA3 string is set (via SetHelloStr), it attempts to convert this string to a
// ClientHelloSpec.
// 2. If a custom ClientHelloID is set (via SetHelloID), it attempts to convert
// this ID to a ClientHelloSpec.
// 3. If none of the above conditions are met, it returns the currently set ClientHelloSpec.
//
// This method returns the selected ClientHelloSpec along with an error value. If an error occurs
// during conversion, it returns the error.
func (j *ja3) getSpec() (utls.ClientHelloSpec, error) {
	switch {
	case j.str != "":
		return stringToSpec(j.str)
	case !j.id.IsSet():
		return utls.UTLSIdToSpec(j.id)
	}

	return j.spec, nil
}

// setAlpnProtocolToHTTP1 updates the ALPN protocols of the provided ClientHelloSpec to include
// "http/1.1".
//
// It modifies the ALPN protocols of the first ALPNExtension found in the extensions of the
// provided spec.
// If no ALPNExtension is found, it does nothing.
//
// Note that this function modifies the provided spec in-place.
func setAlpnProtocolToHTTP1(utlsSpec *utls.ClientHelloSpec) {
	for _, Extension := range utlsSpec.Extensions {
		alpns, ok := Extension.(*utls.ALPNExtension)
		if ok {
			if i := slices.Index(alpns.AlpnProtocols, "h2"); i != -1 {
				alpns.AlpnProtocols = slices.Delete(alpns.AlpnProtocols, i, i+1)
			}

			if !slices.Contains(alpns.AlpnProtocols, "http/1.1") {
				alpns.AlpnProtocols = append([]string{"http/1.1"}, alpns.AlpnProtocols...)
			}

			break
		}
	}
}

func processSpec(ja3Spec utls.ClientHelloSpec) utls.ClientHelloSpec {
	utlsSpec := utls.ClientHelloSpec(ja3Spec)
	total := len(ja3Spec.Extensions)

	utlsSpec.Extensions = make([]utls.TLSExtension, total)

	lastIndex := -1

	for i := 0; i < total; i++ {
		extID, extType := getExtensionID(ja3Spec.Extensions[i])
		if extID == 41 {
			lastIndex = i
		}

		switch extType {
		case 3:
			return utls.ClientHelloSpec{}
		case 0:
			if ext, _ := createExtension(extID, extensionOption{ext: ja3Spec.Extensions[i]}); ext != nil {
				utlsSpec.Extensions[i] = ext
			} else {
				utlsSpec.Extensions[i] = ja3Spec.Extensions[i]
			}
		default:
			utlsSpec.Extensions[i] = ja3Spec.Extensions[i]
		}
	}

	if lastIndex != -1 {
		utlsSpec.Extensions[lastIndex], utlsSpec.Extensions[total-1] = utlsSpec.Extensions[total-1], utlsSpec.Extensions[lastIndex]
	}

	return utlsSpec
}

// StringToSpec creates a ClientHelloSpec based on a JA3 string.
func stringToSpec(ja3Str string) (utls.ClientHelloSpec, error) {
	var clientHelloSpec utls.ClientHelloSpec

	tokens := strings.Split(ja3Str, ",")
	if len(tokens) != 5 {
		return clientHelloSpec, errors.New("ja3Str format error")
	}

	ver, err := strconv.ParseUint(tokens[0], 10, 16)
	if err != nil {
		return clientHelloSpec, errors.New("ja3Str tlsVersion error")
	}

	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	pointFormats := strings.Split(tokens[4], "-")

	tlsVerMax, tlsVerMin, tlsSuppVersExt, err := createTlSVersion(uint16(ver))
	if err != nil {
		return clientHelloSpec, err
	}

	clientHelloSpec.TLSVersMax = tlsVerMax
	clientHelloSpec.TLSVersMin = tlsVerMin

	if clientHelloSpec.CipherSuites, err = createCiphers(ciphers); err != nil {
		return clientHelloSpec, err
	}

	curvesExtension, err := createCurves(curves)
	if err != nil {
		return clientHelloSpec, err
	}

	pointExtension, err := createPointFormats(pointFormats)
	if err != nil {
		return clientHelloSpec, err
	}

	clientHelloSpec.CompressionMethods = []byte{0}
	clientHelloSpec.GetSessionID = sha256.Sum256
	clientHelloSpec.Extensions, err = createExtensions(extensions, tlsSuppVersExt, curvesExtension, pointExtension)

	return clientHelloSpec, err
}

// TLSVersion，Ciphers，Extensions，EllipticCurves，EllipticCurvePointFormats
func createTlSVersion(ver uint16) (uint16, uint16, utls.TLSExtension, error) {
	var (
		tlsVerMin      uint16
		tlsVerMax      uint16
		tlsSuppVersExt utls.TLSExtension
		err            error
	)

	switch ver {
	case utls.VersionTLS13:
		tlsVerMax = utls.VersionTLS13
		tlsVerMin = utls.VersionTLS12
		tlsSuppVersExt = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			},
		}
	case utls.VersionTLS12:
		tlsVerMax = utls.VersionTLS12
		tlsVerMin = utls.VersionTLS11
		tlsSuppVersExt = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS12,
				utls.VersionTLS11,
			},
		}
	case utls.VersionTLS11:
		tlsVerMax = utls.VersionTLS11
		tlsVerMin = utls.VersionTLS10
		tlsSuppVersExt = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS11,
				utls.VersionTLS10,
			},
		}
	default:
		err = errors.New("ja3Str tls version error")
	}

	return tlsVerMax, tlsVerMin, tlsSuppVersExt, err
}

func createCiphers(ciphers []string) ([]uint16, error) {
	cipherSuites := []uint16{utls.GREASE_PLACEHOLDER}

	for _, val := range ciphers {
		n, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return nil, errors.New("ja3Str cipherSuites error")
		}

		cipherSuites = append(cipherSuites, uint16(n))
	}

	return cipherSuites, nil
}

func createPointFormats(points []string) (utls.TLSExtension, error) {
	supportedPoints := []uint8{}

	for _, val := range points {
		n, err := strconv.ParseUint(val, 10, 8)
		if err != nil {
			return nil, errors.New("ja3Str point error")
		}

		supportedPoints = append(supportedPoints, uint8(n))
	}

	return &utls.SupportedPointsExtension{SupportedPoints: supportedPoints}, nil
}

func IsGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func createExtensions(extensions []string, tlsExtension, curvesExtension, pointExtension utls.TLSExtension) ([]utls.TLSExtension, error) {
	allExtensions := []utls.TLSExtension{&utls.UtlsGREASEExtension{}}

	for _, extension := range extensions {
		var extensionID uint16

		n, err := strconv.ParseUint(extension, 10, 16)
		if err != nil {
			return nil, errors.New("ja3Str extension error, utls not support: " + extension)
		}

		extensionID = uint16(n)

		switch extensionID {
		case 10:
			allExtensions = append(allExtensions, curvesExtension)
		case 11:
			allExtensions = append(allExtensions, pointExtension)
		case 43:
			allExtensions = append(allExtensions, tlsExtension)
		default:
			ext, _ := createExtension(extensionID)
			if ext == nil {
				if IsGREASEUint16(extensionID) {
					allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}

				allExtensions = append(allExtensions, &utls.GenericExtension{Id: extensionID})
				continue
			}

			if extensionID == 21 {
				allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
			}

			allExtensions = append(allExtensions, ext)
		}
	}

	return allExtensions, nil
}

func createCurves(curves []string) (curvesExtension utls.TLSExtension, err error) {
	curveIds := []utls.CurveID{utls.GREASE_PLACEHOLDER}

	for _, val := range curves {
		n, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return nil, errors.New("ja3Str curves error")
		}

		curveIds = append(curveIds, utls.CurveID(uint16(n)))
	}

	return &utls.SupportedCurvesExtension{Curves: curveIds}, nil
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type extensionOption struct {
	data []byte
	ext  utls.TLSExtension
}

func createExtension(extensionID uint16, options ...extensionOption) (utls.TLSExtension, bool) {
	var option extensionOption
	if len(options) > 0 {
		option = options[0]
	}
	switch extensionID {
	case 0:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SNIExtension))
			return &extV, true
		}
		extV := new(utls.SNIExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 5:
		if option.ext != nil {
			extV := *(option.ext.(*utls.StatusRequestExtension))
			return &extV, true
		}
		extV := new(utls.StatusRequestExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 10:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedCurvesExtension))
			return &extV, true
		}
		extV := new(utls.SupportedCurvesExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 11:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedPointsExtension))
			return &extV, true
		}
		extV := new(utls.SupportedPointsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 13:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SignatureAlgorithmsExtension))
			return &extV, true
		}
		extV := new(utls.SignatureAlgorithmsExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}
		}
		return extV, true
	case 16:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ALPNExtension))
			return &extV, true
		}
		extV := new(utls.ALPNExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.AlpnProtocols = []string{"h2", "http/1.1"}
		}
		return extV, true
	case 17:
		if option.ext != nil {
			extV := *(option.ext.(*utls.StatusRequestV2Extension))
			return &extV, true
		}
		extV := new(utls.StatusRequestV2Extension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 18:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SCTExtension))
			return &extV, true
		}
		extV := new(utls.SCTExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 21:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsPaddingExtension))
			return &extV, true
		}
		extV := new(utls.UtlsPaddingExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.GetPaddingLen = utls.BoringPaddingStyle
		}
		return extV, true
	case 23:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ExtendedMasterSecretExtension))
			return &extV, true
		}
		extV := new(utls.ExtendedMasterSecretExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 24:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeTokenBindingExtension))
			return &extV, true
		}
		extV := new(utls.FakeTokenBindingExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 27:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsCompressCertExtension))
			return &extV, true
		}
		extV := new(utls.UtlsCompressCertExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Algorithms = []utls.CertCompressionAlgo{utls.CertCompressionBrotli}
		}
		return extV, true
	case 28:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeRecordSizeLimitExtension))
			return &extV, true
		}
		extV := new(utls.FakeRecordSizeLimitExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 34:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeDelegatedCredentialsExtension))
			return &extV, true
		}
		extV := new(utls.FakeDelegatedCredentialsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 35:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SessionTicketExtension))
			return &extV, true
		}
		extV := new(utls.SessionTicketExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 41:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsPreSharedKeyExtension))
			return &extV, true
		}
		extV := new(utls.UtlsPreSharedKeyExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 43:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedVersionsExtension))
			return &extV, true
		}
		extV := new(utls.SupportedVersionsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 44:
		if option.ext != nil {
			extV := *(option.ext.(*utls.CookieExtension))
			return &extV, true
		}
		extV := new(utls.CookieExtension)
		if option.data != nil {
			extV.Cookie = option.data
		}
		return extV, true
	case 45:
		if option.ext != nil {
			extV := *(option.ext.(*utls.PSKKeyExchangeModesExtension))
			return &extV, true
		}
		extV := new(utls.PSKKeyExchangeModesExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Modes = []uint8{utls.PskModeDHE}
		}
		return extV, true
	case 50:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SignatureAlgorithmsCertExtension))
			return &extV, true
		}
		extV := new(utls.SignatureAlgorithmsCertExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}
		}
		return extV, true
	case 51:
		if option.ext != nil {
			extt := new(utls.KeyShareExtension)
			if keyShares := option.ext.(*utls.KeyShareExtension).KeyShares; keyShares != nil {
				extt.KeyShares = make([]utls.KeyShare, len(keyShares))
				copy(extt.KeyShares, keyShares)
			}
			return extt, true
		}
		extV := new(utls.KeyShareExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.KeyShares = []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}
		}
		return extV, true
	case 57:
		if option.ext != nil {
			extV := *(option.ext.(*utls.QUICTransportParametersExtension))
			return &extV, true
		}
		return new(utls.QUICTransportParametersExtension), true
	case 13172:
		if option.ext != nil {
			extV := *(option.ext.(*utls.NPNExtension))
			return &extV, true
		}
		extV := new(utls.NPNExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 17513:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ApplicationSettingsExtension))
			return &extV, true
		}
		extV := new(utls.ApplicationSettingsExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedProtocols = []string{"h2", "http/1.1"}
		}
		return extV, true
	case 30031:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeChannelIDExtension))
			return &extV, true
		}
		extV := new(utls.FakeChannelIDExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.OldExtensionID = true
		}
		return extV, true
	case 30032:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeChannelIDExtension))
			return &extV, true
		}
		extV := new(utls.FakeChannelIDExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 65281:
		if option.ext != nil {
			extV := *(option.ext.(*utls.RenegotiationInfoExtension))
			return &extV, true
		}
		extV := new(utls.RenegotiationInfoExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Renegotiation = utls.RenegotiateOnceAsClient
		}
		return extV, true
	default:
		if option.data != nil {
			return &utls.GenericExtension{
				Id:   extensionID,
				Data: option.data,
			}, false
		}
		return option.ext, false
	}
}

// type,0: is ext, 1：custom ext，2：grease ext , 3：unknow ext
func getExtensionID(extension utls.TLSExtension) (uint16, uint8) {
	switch ext := extension.(type) {
	case *utls.SNIExtension:
		return 0, 0
	case *utls.StatusRequestExtension:
		return 5, 0
	case *utls.SupportedCurvesExtension:
		return 10, 0
	case *utls.SupportedPointsExtension:
		return 11, 0
	case *utls.SignatureAlgorithmsExtension:
		return 13, 0
	case *utls.ALPNExtension:
		return 16, 0
	case *utls.StatusRequestV2Extension:
		return 17, 0
	case *utls.SCTExtension:
		return 18, 0
	case *utls.UtlsPaddingExtension:
		return 21, 0
	case *utls.ExtendedMasterSecretExtension:
		return 23, 0
	case *utls.FakeTokenBindingExtension:
		return 24, 0
	case *utls.UtlsCompressCertExtension:
		return 27, 0
	case *utls.FakeDelegatedCredentialsExtension:
		return 34, 0
	case *utls.SessionTicketExtension:
		return 35, 0
	case *utls.UtlsPreSharedKeyExtension:
		return 41, 0
	case *utls.SupportedVersionsExtension:
		return 43, 0
	case *utls.CookieExtension:
		return 44, 0
	case *utls.PSKKeyExchangeModesExtension:
		return 45, 0
	case *utls.SignatureAlgorithmsCertExtension:
		return 50, 0
	case *utls.KeyShareExtension:
		return 51, 0
	case *utls.QUICTransportParametersExtension:
		return 57, 0
	case *utls.NPNExtension:
		return 13172, 0
	case *utls.ApplicationSettingsExtension:
		return 17513, 0
	case *utls.FakeChannelIDExtension:
		if ext.OldExtensionID {
			return 30031, 0
		} else {
			return 30031, 0
		}
	case *utls.FakeRecordSizeLimitExtension:
		return 28, 0
	case *utls.RenegotiationInfoExtension:
		return 65281, 0
	case *utls.GenericExtension:
		return ext.Id, 1
	case *utls.UtlsGREASEExtension:
		return 0, 2
	default:
		return 0, 3
	}
}

func (j *ja3) Android() *Options          { return j.SetHelloID(utls.HelloAndroid_11_OkHttp) }
func (j *ja3) Chrome() *Options           { return j.SetHelloID(utls.HelloChrome_Auto) }
func (j *ja3) Chrome58() *Options         { return j.SetHelloID(utls.HelloChrome_58) }
func (j *ja3) Chrome62() *Options         { return j.SetHelloID(utls.HelloChrome_62) }
func (j *ja3) Chrome70() *Options         { return j.SetHelloID(utls.HelloChrome_70) }
func (j *ja3) Chrome72() *Options         { return j.SetHelloID(utls.HelloChrome_72) }
func (j *ja3) Chrome83() *Options         { return j.SetHelloID(utls.HelloChrome_83) }
func (j *ja3) Chrome87() *Options         { return j.SetHelloID(utls.HelloChrome_87) }
func (j *ja3) Chrome96() *Options         { return j.SetHelloID(utls.HelloChrome_96) }
func (j *ja3) Chrome100() *Options        { return j.SetHelloID(utls.HelloChrome_100) }
func (j *ja3) Chrome102() *Options        { return j.SetHelloID(utls.HelloChrome_102) }
func (j *ja3) Chrome106() *Options        { return j.SetHelloID(utls.HelloChrome_106_Shuffle) }
func (j *ja3) Edge() *Options             { return j.SetHelloID(utls.HelloEdge_106) }
func (j *ja3) Edge85() *Options           { return j.SetHelloID(utls.HelloEdge_85) }
func (j *ja3) Edge106() *Options          { return j.SetHelloID(utls.HelloEdge_106) }
func (j *ja3) Firefox() *Options          { return j.SetHelloID(utls.HelloFirefox_Auto) }
func (j *ja3) Firefox55() *Options        { return j.SetHelloID(utls.HelloFirefox_55) }
func (j *ja3) Firefox56() *Options        { return j.SetHelloID(utls.HelloFirefox_56) }
func (j *ja3) Firefox63() *Options        { return j.SetHelloID(utls.HelloFirefox_63) }
func (j *ja3) Firefox65() *Options        { return j.SetHelloID(utls.HelloFirefox_65) }
func (j *ja3) Firefox99() *Options        { return j.SetHelloID(utls.HelloFirefox_99) }
func (j *ja3) Firefox102() *Options       { return j.SetHelloID(utls.HelloFirefox_102) }
func (j *ja3) Firefox105() *Options       { return j.SetHelloID(utls.HelloFirefox_105) }
func (j *ja3) IOS() *Options              { return j.SetHelloID(utls.HelloIOS_Auto) }
func (j *ja3) IOS11() *Options            { return j.SetHelloID(utls.HelloIOS_11_1) }
func (j *ja3) IOS12() *Options            { return j.SetHelloID(utls.HelloIOS_12_1) }
func (j *ja3) IOS13() *Options            { return j.SetHelloID(utls.HelloIOS_13) }
func (j *ja3) Randomized() *Options       { return j.SetHelloID(utls.HelloRandomized) }
func (j *ja3) RandomizedALPN() *Options   { return j.SetHelloID(utls.HelloRandomizedALPN) }
func (j *ja3) RandomizedNoALPN() *Options { return j.SetHelloID(utls.HelloRandomizedNoALPN) }
func (j *ja3) Safari() *Options           { return j.SetHelloID(utls.HelloSafari_Auto) }
