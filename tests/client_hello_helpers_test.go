package surf_test

import (
	"bytes"
	"net"
)

type clientHelloConn struct {
	net.Conn
	hellos chan<- recordedClientHello
}

type recordedClientHello struct {
	extensions []uint16
	raw        []byte
}

func (c *clientHelloConn) Write(p []byte) (int, error) {
	if extensions, ok := readClientHelloExtensions(bytes.NewReader(p)); ok {
		c.hellos <- recordedClientHello{extensions: extensions, raw: bytes.Clone(p[5:])}
	}
	return c.Conn.Write(p)
}
