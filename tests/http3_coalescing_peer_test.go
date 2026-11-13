package surf_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

type coalescingObservation struct {
	connection int32
	method     string
	authority  string
	body       string
	fields     []qpack.HeaderField
}

type coalescingTestPeer struct {
	port     string
	roots    *x509.CertPool
	cert     tls.Certificate
	requests chan coalescingObservation
	closed   chan error
	accepted atomic.Int32
	keyLog   io.Writer
}

// A real, trusted TLS peer independently decodes H3/QPACK and records which
// QUIC connection carried each authority. Server extensions use public APIs.
func newCoalescingTestPeer(t *testing.T, options string, origins func(string) []string, status func(coalescingObservation) int, controlOverride ...func(string) []byte) *coalescingTestPeer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Surf coalescing test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames:    []string{"a.test", "b.test", "c.test", "*.example", "localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{http3.NextProtoH3}}
	// Optional diagnostic output for independent tcpdump/Wireshark validation.
	// Ordinary test runs do not write traffic secrets or capture artifacts.
	if path := os.Getenv("SURF_COALESCING_KEYLOG"); path != "" {
		log, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		require.NoError(t, err)
		t.Cleanup(func() { log.Close() })
		tlsConfig.KeyLogWriter = log
	}
	config := &quic.Config{}
	if options != "" {
		config.ServerTransportParameters = &transportparams.Layout{Additional: []transportparams.Parameter{{ID: 0x3128, Value: []byte(options)}}}
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, config)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	p := &coalescingTestPeer{port: port, roots: roots, cert: certificate, requests: make(chan coalescingObservation, 256), closed: make(chan error, 64)}
	p.keyLog = tlsConfig.KeyLogWriter
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	var connections []*quic.Conn
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			c.CloseWithError(0, "test finished")
		}
	})
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			id := p.accepted.Add(1)
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			go func() {
				control, err := conn.OpenUniStream()
				if err != nil {
					return
				}
				setup := []byte{0, 4, 0} // Control stream, empty SETTINGS.
				if len(controlOverride) > 0 {
					setup = controlOverride[0](port)
				}
				if origins != nil {
					var payload []byte
					for _, origin := range origins(port) {
						payload = binary.BigEndian.AppendUint16(payload, uint16(len(origin)))
						payload = append(payload, origin...)
					}
					setup = quicvarint.Append(setup, 12)
					setup = quicvarint.Append(setup, uint64(len(payload)))
					setup = append(setup, payload...)
				}
				if _, err := control.Write(setup); err != nil {
					return
				}
				if len(controlOverride) > 0 {
					<-conn.Context().Done() // Malformed-peer fixtures never race a response.
					p.closed <- context.Cause(conn.Context())
					return
				}
				go func() {
					for {
						stream, err := conn.AcceptUniStream(ctx)
						if err != nil {
							return
						}
						go io.Copy(io.Discard, stream)
					}
				}()
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go p.serveStream(stream, id, status)
				}
			}()
		}
	}()
	return p
}

func (p *coalescingTestPeer) serveStream(stream *quic.Stream, id int32, status func(coalescingObservation) int) {
	defer stream.Close()
	observation := coalescingObservation{connection: id}
	reader := quicvarint.NewReader(stream)
	for {
		typ, err := quicvarint.Read(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		n, err := quicvarint.Read(reader)
		if err != nil || n > 1<<20 {
			return
		}
		data := make([]byte, int(n))
		if _, err := io.ReadFull(stream, data); err != nil {
			return
		}
		switch typ {
		case 1:
			decode := qpack.NewDecoder().Decode(data)
			var fields []qpack.HeaderField
			for {
				field, err := decode()
				if err == io.EOF {
					break
				}
				if err != nil {
					return
				}
				fields = append(fields, field)
			}
			observation.fields = fields
			for _, field := range fields {
				if field.Name == ":method" {
					observation.method = field.Value
				}
				if field.Name == ":authority" {
					observation.authority = field.Value
				}
			}
		case 0:
			observation.body += string(data)
		}
	}
	p.requests <- observation
	code := 200
	if status != nil {
		code = status(observation)
	}
	var header bytes.Buffer
	encoder := qpack.NewEncoder(&header)
	encoder.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(code)})
	encoder.WriteField(qpack.HeaderField{Name: "content-length", Value: "2"})
	frame := quicvarint.Append(nil, 1)
	frame = quicvarint.Append(frame, uint64(header.Len()))
	frame = append(frame, header.Bytes()...)
	if observation.method != http.MethodHead {
		frame = append(frame, 0, 2, 'o', 'k')
	}
	stream.Write(frame)
}

type coalescingDNS struct {
	address string
	mu      sync.Mutex
	queries map[string]int
}

func newCoalescingDNS(t *testing.T, hosts map[string][4]byte) *coalescingDNS {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { socket.Close() })
	d := &coalescingDNS{address: socket.LocalAddr().String(), queries: make(map[string]int)}
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, from, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			name := strings.TrimSuffix(q.Name.String(), ".")
			d.mu.Lock()
			d.queries[name]++
			d.mu.Unlock()
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			if ip, ok := hosts[name]; ok {
				if q.Type == dnsmessage.TypeA {
					reply.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip}}}
				}
			} else {
				reply.RCode = dnsmessage.RCodeNameError
			}
			data, err := reply.Pack()
			if err == nil {
				socket.WriteTo(data, from)
			}
		}
	}()
	return d
}

func (d *coalescingDNS) count(host string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[host]
}

func coalescingBuilder(p *coalescingTestPeer, d *coalescingDNS) *surf.Builder {
	return surf.NewClient().Builder().Impersonate().Chrome().Proxy("").DNS(g.String(d.address)).
		ForceHTTP3().HTTP3Settings().Discovery(false).Set().TLSConfig(&tls.Config{RootCAs: p.roots, KeyLogWriter: p.keyLog}).Timeout(5 * time.Second)
}

func coalescingGet(t *testing.T, client *surf.Client, host, port string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", "https://"+net.JoinHostPort(host, port)+"/", nil)
	require.NoError(t, err)
	response, err := client.GetClient().Do(req)
	if err == nil {
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	return response, err
}

func coalescingObserved(t *testing.T, p *coalescingTestPeer) coalescingObservation {
	t.Helper()
	select {
	case observation := <-p.requests:
		return observation
	case <-time.After(5 * time.Second):
		t.Fatal("no independently decoded HTTP/3 request")
		return coalescingObservation{}
	}
}
