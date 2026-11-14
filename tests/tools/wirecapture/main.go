package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	stdhttp "net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlogwriter"
)

type captureServer struct {
	mu            sync.Mutex
	currentLabel  string
	completed     bool
	failure       string
	requests      []observedRequest
	errors        []string
	capacity      uint64
	records       *os.File
	packetRecords *os.File
	responseBytes int
	scenarioMode  string
	frameRecords  *os.File
	packets       *packetCapture
	tlsConfig     *tls.Config
}

func (s *captureServer) label() string { s.mu.Lock(); defer s.mu.Unlock(); return s.currentLabel }
func (s *captureServer) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append(s.errors, err.Error())
}

func certificate(directory string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Surf temporary capture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Surf local wire capture"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(filepath.Join(directory, "certificate.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		return tls.Certificate{}, "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	digest := sha256.Sum256(spki)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, base64.StdEncoding.EncodeToString(digest[:]), nil
}

func main() {
	out := flag.String("out", "", "private capture directory")
	protocol := flag.String("protocol", "h2", "h2 or h3")
	capacity := flag.Uint64("capacity", 4096, "server request-decoder table capacity")
	replay := flag.String("replay", "", "replay request JSONL against an already running origin")
	origin := flag.String("origin", "", "origin for replay")
	browser := flag.String("browser", "chrome", "Surf profile: chrome or firefox")
	profileOS := flag.String("os", "macos", "Surf desktop OS: macos or windows")
	endpoint := flag.String("probe-endpoint", "", "probe a public TLS/HTTP2 endpoint and save JSON under out")
	stock := flag.Bool("stock", false, "use the stock Surf headers instead of exact captured headers")
	allowFallback := flag.Bool("allow-fallback", false, "record fallback protocols instead of requiring the selected protocol")
	connectionRacing := flag.Bool("connection-racing", false, "enable connection-only HTTP/3/TCP competition for Surf replay")
	responseBytes := flag.Int("response-bytes", 0, "synthetic /step/0 response bytes for ACK observations")
	legacyAckMinimum := flag.Duration("legacy-ack-frequency-min", 0, "advertise a legacy ACK_FREQUENCY receiver minimum (HTTP/3 only)")
	udpDelay := flag.Duration("udp-delay", 0, "one-way pipelined UDP delay, e.g. 10ms")
	udpDropFirst := flag.Uint64("udp-drop-first", 0, "drop the first N UDP datagrams per remote/direction")
	udpJitter := flag.Duration("udp-jitter", 0, "deterministic per-flow jitter bounded by the one-way delay")
	udpReorderEvery := flag.Uint64("udp-reorder-every", 0, "delay every Nth datagram to allow overtaking; zero disables")
	udpDropEvery := flag.Uint64("udp-drop-every", 0, "drop every Nth UDP datagram per remote/direction; zero disables")
	scenarioMode := flag.String("scenario", "headers", "headers, uploads or priorities (HTTP/3 only)")
	bulkPlan := flag.String("bulk-plan", "", "verified public HTTP/3 bulk transfer plan JSON")
	bulkFields := flag.String("bulk-fields", "", "native ordered fields from bulk-reduce.mjs")
	flag.Parse()
	if *bulkPlan != "" {
		if err := replayBulk(*bulkPlan, *bulkFields, *browser, *out); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *profileOS != "macos" && *profileOS != "windows" {
		log.Fatal("invalid desktop OS")
	}
	if *endpoint != "" {
		if err := probeSurfEndpoint(*endpoint, *out, *browser, *profileOS, *protocol); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *replay != "" {
		if err := replaySurf(*replay, *origin, *browser, *protocol, *stock, *scenarioMode, *allowFallback, *profileOS, *connectionRacing); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *udpJitter < 0 || *udpJitter > *udpDelay || *udpReorderEvery == 1 || *udpDelay < 0 || *udpDelay > time.Second || *udpDropEvery == 1 || *udpDropFirst > 10 {
		log.Fatal("invalid UDP impairment settings")
	}
	if (*scenarioMode != "headers" && *scenarioMode != "uploads" && *scenarioMode != "priorities") || (*scenarioMode != "headers" && *protocol != "h3") || *out == "" || (*protocol != "h2" && *protocol != "h3") || *responseBytes < 0 || *responseBytes > 16<<20 {
		log.Fatal("out and valid protocol are required")
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		log.Fatal(err)
	}
	cert, spki, err := certificate(*out)
	if err != nil {
		log.Fatal(err)
	}
	keys, err := os.OpenFile(filepath.Join(*out, "tls.keys"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer keys.Close()
	packets, err := newPacketCapture(filepath.Join(*out, "wire.pcap"))
	if err != nil {
		log.Fatal(err)
	}
	defer packets.Close()
	records, err := os.OpenFile(filepath.Join(*out, "requests.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer records.Close()
	packetRecords, err := os.OpenFile(filepath.Join(*out, "transport.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer packetRecords.Close()
	frameRecords, err := os.OpenFile(filepath.Join(*out, "frames.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer frameRecords.Close()
	s := &captureServer{scenarioMode: *scenarioMode, frameRecords: frameRecords, capacity: *capacity, packets: packets, records: records, packetRecords: packetRecords, responseBytes: *responseBytes, currentLabel: "browser", tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, KeyLogWriter: &lockedWriter{writer: keys}}}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	go s.serveTCP(tcp)
	port := tcp.Addr().(*net.TCPAddr).Port
	var h3 *http3.Server
	if *protocol == "h3" {
		udp, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			log.Fatal(err)
		}
		settings := g.NewMapOrd[uint64, uint64]()
		settings.Insert(1, *capacity)
		settings.Insert(7, 16)
		h3 = &http3.Server{TLSConfig: s.tlsConfig.Clone(), QUICConfig: &quic.Config{EnableDatagrams: true, LegacyAckFrequencyMinDelay: *legacyAckMinimum, Tracer: func(_ context.Context, _ bool, id quic.ConnectionID) qlogwriter.Trace {
			return &headerTrace{server: s, label: s.label(), connection: id.String()}
		}}, EnableDatagrams: true, AdditionalSettings: settings,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				return context.WithValue(ctx, connectionKey{}, s.label()+"|"+conn.RemoteAddr().String())
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if s.scenarioMode == "priorities" && r.URL.Path == "/priority.svg" {
					w.Header().Set("Content-Type", "image/svg+xml")
					w.Header().Set("Cache-Control", "no-store")
					io.WriteString(w, `<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8">`)
					for range 16 {
						if _, err := io.WriteString(w, strings.Repeat(" ", 4096)); err != nil {
							return
						}
						w.(http.Flusher).Flush()
						time.Sleep(50 * time.Millisecond)
					}
					io.WriteString(w, `<rect width="8" height="8"/></svg>`)
					return
				}
				if r.Body != nil {
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						s.fail(err)
						return
					}
				}
				headers, body := s.response(r.URL.RequestURI())
				for name, values := range headers {
					w.Header()[name] = values
				}
				w.Write(body)
			})}
		var peer net.PacketConn = &capturedUDP{PacketConn: udp, capture: packets}
		if *udpReorderEvery > 0 || *udpDelay > 0 || *udpDropEvery > 0 || *udpDropFirst > 0 {
			events, err := os.OpenFile(filepath.Join(*out, "network.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				log.Fatal(err)
			}
			shaped := newShapedUDP(peer, *udpDelay, *udpDropEvery, *udpDropFirst, events, networkOptions{Jitter: *udpJitter, ReorderEvery: *udpReorderEvery})
			peer = shaped
			defer func() {
				shaped.Close()
				summary, err := json.MarshalIndent(shaped.summary(), "", "  ")
				if err == nil {
					err = os.WriteFile(filepath.Join(*out, "network-summary.json"), append(summary, '\n'), 0600)
				}
				if err != nil {
					log.Print(err)
				}
				events.Close()
			}()
		}
		go func() {
			if err := h3.Serve(peer); err != nil && err != http.ErrServerClosed {
				s.fail(err)
			}
		}()
		defer h3.Close()
	}
	admin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer admin.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/status", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"complete": s.completed, "failure": s.failure, "errors": s.errors, "requests": s.requests})
	})
	mux.HandleFunc("/label", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		s.mu.Lock()
		s.currentLabel = r.URL.Query().Get("value")
		s.completed = false
		s.failure = ""
		s.mu.Unlock()
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/finish", func(w stdhttp.ResponseWriter, r *stdhttp.Request) { w.Write([]byte("ok")); stop() })
	go stdhttp.Serve(admin, mux)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"origin": fmt.Sprintf("https://127.0.0.1:%d", port), "admin": "http://" + admin.Addr().String(), "port": port, "spki": spki, "certificate": filepath.Join(*out, "certificate.pem"), "protocol": *protocol, "capacity": *capacity, "legacy_ack_frequency_min_us": *legacyAckMinimum / time.Microsecond, "network": map[string]any{"one_way_delay_ms": udpDelay.Milliseconds(), "jitter_ms": float64(*udpJitter) / float64(time.Millisecond), "reorder_every_per_flow_direction": *udpReorderEvery, "drop_every_per_flow_direction": *udpDropEvery, "drop_first_per_flow_direction": *udpDropFirst}})
	<-ctx.Done()
}

type connectionKey struct{}
