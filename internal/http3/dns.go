package h3transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsTypeHTTPS = dnsmessage.TypeHTTPS

// Use the same custom DNS/DoT dial hook as address resolution. The OS resolver
// has no public HTTPS lookup API; on systems without resolv.conf the caller can
// supply HTTPSRecordsLookup. Never silently substitute a third-party resolver.
func httpsLookupForResolver(resolver *net.Resolver) HTTPSRecordsLookup {
	return func(ctx context.Context, host string) ([]HTTPSRecord, error) {
		// RFC 6761 section 6.3: localhost names are resolved locally. Do not
		// wait on an external DNS server for HTTPS records for loopback services.
		name := strings.ToLower(strings.TrimSuffix(host, "."))
		if name == "localhost" || strings.HasSuffix(name, ".localhost") {
			return nil, nil
		}

		servers := systemDNSServers()
		if len(servers) == 0 && resolver != nil && resolver.Dial != nil {
			servers = []string{"127.0.0.1:53"}
		}

		if len(servers) == 0 {
			return nil, errors.New("no system DNS addresses available for HTTPS lookup")
		}

		var last error
		for _, server := range servers {
			records, err := queryHTTPS(ctx, host, server, resolver, 0)
			if err == nil {
				return records, nil
			}

			last = err

			if ctx.Err() != nil {
				break
			}
		}

		return nil, last
	}
}

func systemDNSServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}

	var servers []string
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if _, err := netip.ParseAddr(fields[1]); err == nil {
				servers = append(servers, net.JoinHostPort(fields[1], "53"))
			}
		}
	}

	return servers
}

func queryHTTPS(ctx context.Context, host, server string, resolver *net.Resolver, depth int) ([]HTTPSRecord, error) {
	if depth >= 8 {
		return nil, errors.New("HTTPS alias chain exceeds limit")
	}

	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}

	id := uint16(rand.UintN(1 << 16))

	query := dnsmessage.Message{
		ID: id, RecursionDesired: true,
		Questions: []dnsmessage.Question{{Name: name, Type: dnsTypeHTTPS, Class: dnsmessage.ClassINET}},
	}

	data, err := query.Pack()
	if err != nil {
		return nil, err
	}

	message, err := exchangeHTTPS(ctx, data, server, "udp", resolver)
	if err != nil {
		return nil, err
	}

	if message.Truncated {
		message, err = exchangeHTTPS(ctx, data, server, "tcp", resolver)
		if err != nil {
			return nil, err
		}
	}

	if !message.Response || message.ID != id || message.OpCode != 0 || message.Truncated ||
		len(message.Questions) != 1 ||
		message.Questions[0].Type != dnsTypeHTTPS ||
		message.Questions[0].Class != dnsmessage.ClassINET ||
		!strings.EqualFold(message.Questions[0].Name.String(), name.String()) {
		return nil, errors.New("invalid HTTPS DNS response")
	}

	if message.RCode == dnsmessage.RCodeNameError {
		return nil, nil
	}

	if message.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("HTTPS DNS response: %s", message.RCode)
	}

	var records []HTTPSRecord
	for _, answer := range message.Answers {
		if !strings.EqualFold(answer.Header.Name.String(), name.String()) ||
			answer.Header.Class != dnsmessage.ClassINET {
			continue
		}

		if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
			resolved, err := queryHTTPS(ctx, cname.CNAME.String(), server, resolver, depth+1)
			for i := range resolved {
				resolved[i].TTL = min(resolved[i].TTL, time.Duration(answer.Header.TTL)*time.Second)
			}

			return resolved, err
		}

		raw, ok := answer.Body.(*dnsmessage.UnknownResource)
		if !ok || answer.Header.Type != dnsTypeHTTPS {
			continue
		}

		record, err := parseHTTPSRecord(raw.Data, time.Duration(answer.Header.TTL)*time.Second)
		if err != nil {
			continue
		} // RFC 9460: malformed bindings are unusable.

		if record.Priority == 0 {
			if record.Target == "." {
				return nil, nil
			}

			resolved, err := queryHTTPS(ctx, record.Target, server, resolver, depth+1)
			for i := range resolved {
				resolved[i].TTL = min(resolved[i].TTL, record.TTL)
			}

			return resolved, err
		}

		if record.Target == "." {
			record.Target = answer.Header.Name.String()
		}

		records = append(records, record)
	}

	return records, nil
}

func exchangeHTTPS(
	ctx context.Context,
	data []byte,
	server, network string,
	resolver *net.Resolver,
) (dnsmessage.Message, error) {
	var message dnsmessage.Message
	var conn net.Conn
	var err error
	if resolver != nil && resolver.Dial != nil {
		conn, err = resolver.Dial(ctx, network, server)
	} else {
		conn, err = new(net.Dialer).DialContext(ctx, network, server)
	}

	if err != nil {
		return message, err
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, d)
	}

	if err = conn.SetDeadline(deadline); err != nil {
		return message, err
	}

	_, packet := conn.(net.PacketConn)
	var response []byte

	if packet {
		if n, e := conn.Write(data); e != nil {
			return message, e
		} else if n != len(data) {
			return message, io.ErrShortWrite
		}

		response = make([]byte, 65535)
		n, e := conn.Read(response)
		if e != nil {
			return message, e
		}

		response = response[:n]
	} else {
		framed := make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(framed, uint16(len(data)))
		copy(framed[2:], data)

		for len(framed) > 0 {
			n, e := conn.Write(framed)
			if e != nil {
				return message, e
			}

			if n == 0 {
				return message, io.ErrShortWrite
			}

			framed = framed[n:]
		}

		var prefix [2]byte
		if _, err = io.ReadFull(conn, prefix[:]); err != nil {
			return message, err
		}

		response = make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
		if _, err = io.ReadFull(conn, response); err != nil {
			return message, err
		}
	}

	return unpackHTTPSMessage(response)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}

	return b
}

// Read HTTPS RDATA without decompression so the strict binding decoder can
// reject compressed TargetName (RFC 9460 section 2.2). The official parser owns
// all DNS header, owner-name, section and bounds handling.
func unpackHTTPSMessage(data []byte) (dnsmessage.Message, error) {
	var message dnsmessage.Message
	var parser dnsmessage.Parser
	var err error

	if message.Header, err = parser.Start(data); err != nil {
		return message, err
	}

	if message.Questions, err = parser.AllQuestions(); err != nil {
		return message, err
	}

	for {
		header, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if err != nil {
			return message, err
		}

		if header.Type == dnsTypeHTTPS {
			raw, err := parser.UnknownResource()
			if err != nil {
				return message, err
			}

			message.Answers = append(message.Answers, dnsmessage.Resource{Header: header, Body: &raw})
		} else {
			answer, err := parser.Answer()
			if err != nil {
				return message, err
			}

			message.Answers = append(message.Answers, answer)
		}
	}

	if err = parser.SkipAllAuthorities(); err != nil {
		return message, err
	}

	if err = parser.SkipAllAdditionals(); err != nil {
		return message, err
	}

	return message, nil
}

// RFC 9460 section 2.2 forbids compressed TargetName and requires increasing
// keys. Unknown optional keys are ignored; unsupported mandatory keys are kept
// for selection to reject the binding without rejecting the entire answer.
func parseHTTPSRecord(data []byte, ttl time.Duration) (HTTPSRecord, error) {
	r := HTTPSRecord{TTL: ttl}
	bad := errors.New("invalid HTTPS service binding")
	if len(data) < 3 {
		return r, bad
	}

	r.Priority = binary.BigEndian.Uint16(data)
	data = data[2:]
	var labels []string

	for {
		if len(data) == 0 {
			return r, bad
		}

		n := int(data[0])
		data = data[1:]
		if n == 0 {
			break
		}

		if n > 63 || len(data) < n || len(labels) > 126 {
			return r, bad
		}

		labels = append(labels, string(data[:n]))
		data = data[n:]
	}

	r.Target = strings.Join(labels, ".") + "."
	if len(r.Target) > 254 {
		return r, bad
	}

	var params []dnsmessage.SVCParam
	for len(data) > 0 {
		if len(data) < 4 {
			return r, bad
		}

		key, n := binary.BigEndian.Uint16(data), int(binary.BigEndian.Uint16(data[2:]))
		data = data[4:]
		if len(data) < n {
			return r, bad
		}

		params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamKey(key), Value: data[:n]})
		data = data[n:]
	}

	return parseHTTPSParams(r, params)
}

func parseHTTPSParams(r HTTPSRecord, params []dnsmessage.SVCParam) (HTTPSRecord, error) {
	bad := errors.New("invalid HTTPS service binding")
	last := -1
	present := make(map[uint16]bool)

	for _, param := range params {
		key, value := uint16(param.Key), param.Value
		n := len(value)
		if int(key) <= last {
			return r, bad
		}

		last = int(key)
		present[key] = true

		switch key {
		case 0:
			if n == 0 || n%2 != 0 {
				return r, bad
			}
			for len(value) > 0 {
				k := binary.BigEndian.Uint16(value)
				value = value[2:]
				if k == 0 || len(r.Mandatory) > 0 && k <= r.Mandatory[len(r.Mandatory)-1] {
					return r, bad
				}

				r.Mandatory = append(r.Mandatory, k)
			}
		case 1:
			if n == 0 {
				return r, bad
			}

			for len(value) > 0 {
				l := int(value[0])
				value = value[1:]
				if l == 0 || len(value) < l {
					return r, bad
				}

				r.ALPN = append(r.ALPN, string(value[:l]))
				value = value[l:]
			}
		case 2:
			if n != 0 {
				return r, bad
			}
			r.NoDefaultALPN = true
		case 3:
			if n != 2 {
				return r, bad
			}
			r.Port = binary.BigEndian.Uint16(value)
			if r.Port == 0 {
				return r, bad
			}
		case 4, 6:
			width := 4
			if key == 6 {
				width = 16
			}

			if n == 0 || n%width != 0 {
				return r, bad
			}

			for len(value) > 0 {
				address, ok := netip.AddrFromSlice(value[:width])
				if !ok {
					return r, bad
				}

				if width == 4 {
					r.IPv4Hint = append(r.IPv4Hint, address)
				} else {
					r.IPv6Hint = append(r.IPv6Hint, address)
				}

				value = value[width:]
			}
		case 5:
			if n == 0 {
				return r, bad
			}
			r.ECH = slices.Clone(value)
		}
	}

	for _, key := range r.Mandatory {
		if !present[key] {
			return r, bad
		}
	}

	if r.NoDefaultALPN && len(r.ALPN) == 0 {
		return r, bad
	}

	return r, nil
}
