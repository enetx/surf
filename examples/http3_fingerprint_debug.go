package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"unsafe"

	"github.com/enetx/surf"
	uquic "github.com/enetx/uquic"
)

func main() {
	fmt.Println("=== HTTP/3 Fingerprint Verification ===\n")

	// Test different fingerprints
	testFingerprint("Chrome", buildChromeClient())
	testFingerprint("Firefox", buildFirefoxClient())
	testFingerprint("Chrome with DNS", buildChromeWithDNS())
	testFingerprint("Firefox with SOCKS5H", buildFirefoxWithProxy()) // socks5h
	testFingerprint("Chrome with DNS + SOCKS5H", buildChromeWithDNSAndProxy())

	// Compare fingerprints
	compareFingerprints()
}

func buildChromeClient() *surf.Client {
	return surf.NewClient().
		Builder().
		Impersonate().Chrome().HTTP3().
		// HTTP3Settings().Chrome().Set().
		Build()
}

func buildFirefoxClient() *surf.Client {
	return surf.NewClient().
		Builder().
		Impersonate().FireFox().HTTP3().
		// HTTP3Settings().Firefox().Set().
		Build()
}

func buildChromeWithDNS() *surf.Client {
	return surf.NewClient().
		Builder().
		DNS("8.8.8.8:53").
		Impersonate().Chrome().HTTP3().
		// HTTP3Settings().Chrome().Set().
		Build()
}

func buildFirefoxWithProxy() *surf.Client {
	return surf.NewClient().
		Builder().
		Proxy("socks5h://127.0.0.1:2080"). // важно: socks5h, чтобы не резолвить локально
		Impersonate().FireFox().HTTP3().
		// HTTP3Settings().Firefox().Set().
		Build()
}

func buildChromeWithDNSAndProxy() *surf.Client {
	return surf.NewClient().
		Builder().
		DNS("1.1.1.1:53").
		Proxy("socks5://127.0.0.1:2080"). // socks5
		Impersonate().Chrome().HTTP3().
		// HTTP3Settings().Chrome().Set().
		Build()
}

// --- test & compare ---

func testFingerprint(name string, client *surf.Client) {
	fmt.Printf("=== %s ===\n", name)

	transport := client.GetTransport()
	if transport == nil {
		fmt.Println("✗ Transport not configured")
		return
	}

	spec := getQUICSpecFromTransport(transport)
	if spec == nil {
		fmt.Println("✗ quicSpec is nil or not found")
		return
	}

	// Initial Packet view
	fmt.Printf("Initial Packet Fingerprint:\n")
	fmt.Printf("  SrcConnIDLength: %d\n", spec.InitialPacketSpec.SrcConnIDLength)
	fmt.Printf("  DestConnIDLength: %d\n", spec.InitialPacketSpec.DestConnIDLength)
	fmt.Printf("  InitPacketNumberLength: %d\n", spec.InitialPacketSpec.InitPacketNumberLength)
	fmt.Printf("  InitPacketNumber: %d\n", spec.InitialPacketSpec.InitPacketNumber)
	fmt.Printf("  ClientTokenLength: %d\n", spec.InitialPacketSpec.ClientTokenLength)
	fmt.Printf("  UDPDatagramMinSize: %d\n", spec.UDPDatagramMinSize)

	// TLS ClientHello view (из спека, а не рантайма)
	if spec.ClientHelloSpec != nil {
		fmt.Printf("TLS ClientHello Fingerprint:\n")
		cs := spec.ClientHelloSpec.CipherSuites
		fmt.Printf("  CipherSuites: %d [", len(cs))
		for i, suite := range cs[:min(3, len(cs))] {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("0x%04x", suite)
		}
		if len(cs) > 3 {
			fmt.Printf(", ...")
		}
		fmt.Printf("]\n")
		fmt.Printf("  Extensions: %d\n", len(spec.ClientHelloSpec.Extensions))
		fmt.Printf("  CompressionMethods: %v\n", spec.ClientHelloSpec.CompressionMethods)
	}

	// TLS config presence / ALPN hint
	tlsNextProtos := getTLSNextProtosFromTransport(transport)
	if len(tlsNextProtos) > 0 {
		fmt.Printf("✓ TLS config present (will apply fingerprinting)\n")
		fmt.Printf("  ALPN will be set to: %v\n", tlsNextProtos)
	} else {
		fmt.Printf("✓ TLS config present (ALPN unknown, defaulting later)\n")
		fmt.Printf("  ALPN will be set to: [h3]\n")
	}
	fmt.Printf("  ServerName will be set from target host\n")

	// DNS / Proxy hints
	printDNSAndProxyHints(transport)

	// Stable hash based on the QUICSpec fields only
	hash := calculateFingerprintHash(spec)
	fmt.Printf("Fingerprint Hash: %s\n\n", hash)
}

func compareFingerprints() {
	fmt.Println("=== Fingerprint Comparison ===\n")

	clients := map[string]*surf.Client{
		"Chrome":           buildChromeClient(),
		"Chrome+DNS":       buildChromeWithDNS(),
		"Chrome+DNS+Proxy": buildChromeWithDNSAndProxy(),
		"Firefox":          buildFirefoxClient(),
		"Firefox+Proxy":    buildFirefoxWithProxy(),
	}

	hashes := make(map[string]string)
	for name, client := range clients {
		tr := client.GetTransport()
		spec := getQUICSpecFromTransport(tr)
		if spec == nil {
			continue
		}
		hashes[name] = calculateFingerprintHash(spec)
	}

	// Show
	fmt.Println("Fingerprint Hashes:")
	for name, hash := range hashes {
		fmt.Printf("  %-20s: %s\n", name, hash)
	}

	// Chrome stable regardless of DNS/Proxy?
	if hashes["Chrome"] == hashes["Chrome+DNS"] &&
		hashes["Chrome"] == hashes["Chrome+DNS+Proxy"] {
		fmt.Println("\n✓ Chrome fingerprint preserved with DNS/Proxy")
	} else {
		fmt.Println("\n✗ Chrome fingerprint changed with DNS/Proxy!")
		fmt.Printf("  Chrome:            %s\n", hashes["Chrome"])
		fmt.Printf("  Chrome+DNS:        %s\n", hashes["Chrome+DNS"])
		fmt.Printf("  Chrome+DNS+Proxy:  %s\n", hashes["Chrome+DNS+Proxy"])
	}

	// Firefox stable with proxy?
	if hashes["Firefox"] == hashes["Firefox+Proxy"] {
		fmt.Println("✓ Firefox fingerprint preserved with Proxy")
	} else {
		fmt.Println("✗ Firefox fingerprint changed with Proxy!")
		fmt.Printf("  Firefox:       %s\n", hashes["Firefox"])
		fmt.Printf("  Firefox+Proxy: %s\n", hashes["Firefox+Proxy"])
	}

	// Chrome vs Firefox different?
	if hashes["Chrome"] != hashes["Firefox"] {
		fmt.Println("✓ Chrome and Firefox have different fingerprints")
	} else {
		fmt.Println("✗ Chrome and Firefox have same fingerprint!")
	}
}

// --- helpers: reflection, hashing, output ---

// Надёжно достаём *uquic.QUICSpec из поля транспорта surf (*uquicTransport.quicSpec)
func getQUICSpecFromTransport(tr any) *uquic.QUICSpec {
	v := reflect.ValueOf(tr)
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	f := v.FieldByName("quicSpec")
	if !f.IsValid() || f.IsNil() || f.Kind() != reflect.Ptr {
		return nil
	}
	// f.Pointer() возвращает uintptr (адрес *QUICSpec)
	return (*uquic.QUICSpec)(unsafe.Pointer(f.Pointer()))
}

// вытащить ALPN из tlsConfig.NextProtos, если есть
func getTLSNextProtosFromTransport(tr any) []string {
	v := reflect.ValueOf(tr)
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	tf := v.FieldByName("tlsConfig")
	if !tf.IsValid() || tf.IsNil() {
		return nil
	}
	// tls.Config is a struct pointer; field NextProtos []string
	tc := tf.Elem()
	np := tc.FieldByName("NextProtos")
	if !np.IsValid() {
		return nil
	}
	if np.Kind() != reflect.Slice {
		return nil
	}
	out := make([]string, np.Len())
	for i := 0; i < np.Len(); i++ {
		out[i] = np.Index(i).String()
	}
	return out
}

// Печатаем подсказки про DNS/Proxy, не ломая инкапсуляцию
func printDNSAndProxyHints(tr any) {
	v := reflect.ValueOf(tr)
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	// DNS (dialer.Resolver)
	df := v.FieldByName("dialer")
	if df.IsValid() && !df.IsNil() {
		d := df.Elem()
		rf := d.FieldByName("Resolver")
		if rf.IsValid() && !rf.IsNil() {
			fmt.Printf("✓ Custom DNS configured (will use dialDNS)\n")
		}
	}
	// Proxy (staticProxy)
	pf := v.FieldByName("staticProxy")
	if pf.IsValid() && pf.Kind() == reflect.String {
		if p := pf.String(); p != "" {
			fmt.Printf("✓ Proxy configured: %s\n", p)
			if isSOCKS5Scheme(p) {
				fmt.Printf("  (will use dialSOCKS5)\n")
			}
		}
	}
}

func isSOCKS5Scheme(s string) bool {
	// минимальная проверка схемы
	return len(s) >= 8 && (s[:8] == "socks5://" || (len(s) >= 9 && s[:9] == "socks5h://"))
}

// Представление спека для стабильного хэша (без указателей/рантайма)
type fpView struct {
	// Initial
	SrcConnIDLength        int    `json:"src_cidl"`
	DestConnIDLength       int    `json:"dst_cidl"`
	InitPacketNumberLength uint8  `json:"pn_len"`
	InitPacketNumber       uint64 `json:"pn"`
	ClientTokenLength      int    `json:"ct_len"`
	UDPDatagramMinSize     int    `json:"udp_min"`
	// TLS ClientHello (только структура спека)
	CipherSuites       []uint16 `json:"suites,omitempty"`
	ExtensionsCount    int      `json:"ext_cnt,omitempty"`
	CompressionMethods []uint8  `json:"compr,omitempty"`
}

func viewFromSpec(spec *uquic.QUICSpec) fpView {
	v := fpView{
		SrcConnIDLength:        spec.InitialPacketSpec.SrcConnIDLength,
		DestConnIDLength:       spec.InitialPacketSpec.DestConnIDLength,
		InitPacketNumberLength: uint8(spec.InitialPacketSpec.InitPacketNumberLength),
		InitPacketNumber:       spec.InitialPacketSpec.InitPacketNumber,
		ClientTokenLength:      spec.InitialPacketSpec.ClientTokenLength,
		UDPDatagramMinSize:     spec.UDPDatagramMinSize,
	}
	if ch := spec.ClientHelloSpec; ch != nil {
		v.CipherSuites = append([]uint16{}, ch.CipherSuites...)
		v.ExtensionsCount = len(ch.Extensions)
		v.CompressionMethods = append([]uint8{}, ch.CompressionMethods...)
	}
	return v
}

// Стабильный короткий хэш (первые 8 байт SHA-256 по JSON представлению спека)
func calculateFingerprintHash(spec *uquic.QUICSpec) string {
	v := viewFromSpec(spec)
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

// (опционально) пример проверки: SNI должен быть FQDN, а не IP
func isHostnameFQDN(host string) bool {
	return host != "" && net.ParseIP(host) == nil
}
