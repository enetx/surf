package desktop

import (
	"io"

	"github.com/enetx/surf/profiles/firefox/internal/ech"

	utls "github.com/refraction-networking/utls"
)

// sessionTicketExtension keeps TLS 1.2 tickets available, but omits extension 35
// when uTLS has loaded a TLS 1.3 PSK, matching Firefox's resumed ClientHello.
type sessionTicketExtension struct {
	utls.SessionTicketExtension
	psk         utls.PreSharedKeyExtension
	ech         *utls.GREASEEncryptedClientHelloExtension
	innerLength int
}

// BindClientHello finds the per-connection PSK after uTLS clones the spec.
func (e *sessionTicketExtension) BindClientHello(conn *utls.UConn) {
	hello := conn.HandshakeState.Hello
	e.innerLength = ech.InnerLength(hello.CipherSuites, hello.CompressionMethods, conn.Extensions)

	for _, extension := range conn.Extensions {
		switch extension := extension.(type) {
		case utls.PreSharedKeyExtension:
			e.psk = extension
		case *utls.GREASEEncryptedClientHelloExtension:
			e.ech = extension
		}
	}
}

func (e *sessionTicketExtension) Len() int {
	innerLength := e.innerLength
	if e.psk != nil && e.psk.IsInitialized() {
		ech.SetPayloadLength(e.ech, innerLength+e.psk.Len())
		return 0
	}

	ech.SetPayloadLength(e.ech, innerLength)

	return e.SessionTicketExtension.Len()
}

func (e *sessionTicketExtension) Read(b []byte) (int, error) {
	if e.Len() == 0 {
		return 0, io.EOF
	}

	return e.SessionTicketExtension.Read(b)
}
