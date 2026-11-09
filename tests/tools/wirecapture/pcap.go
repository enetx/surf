package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Captures exact TLS byte streams and QUIC UDP datagrams at the local server.
// IP/TCP envelopes are synthetic: no BPF privileges or personal network traffic
// are needed. This file is suitable for TLS/HTTP decoding, NOT packet timing,
// segmentation, congestion-control, TCP or IP fingerprint comparisons.
type packetCapture struct {
	mu       sync.Mutex
	file     *os.File
	sequence map[string]uint32
	err      error
}

func newPacketCapture(path string) (*packetCapture, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	h := []uint32{0xa1b2c3d4, 0x00040002, 0, 0, 65535, 101} // little-endian pcap, LINKTYPE_RAW
	if err = binary.Write(f, binary.LittleEndian, h); err != nil {
		f.Close()
		return nil, err
	}
	return &packetCapture{file: f, sequence: make(map[string]uint32)}, nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (c *packetCapture) write(protocol byte, source, destination net.Addr, data []byte) {
	if len(data) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	var src, dst net.IP
	var sport, dport int
	if protocol == 6 {
		a, b := source.(*net.TCPAddr), destination.(*net.TCPAddr)
		src, dst, sport, dport = a.IP, b.IP, a.Port, b.Port
	} else {
		a, b := source.(*net.UDPAddr), destination.(*net.UDPAddr)
		src, dst, sport, dport = a.IP, b.IP, a.Port, b.Port
	}
	for len(data) > 0 {
		n := len(data)
		if protocol == 6 && n > 16000 {
			n = 16000
		}
		payload := data[:n]
		data = data[n:]
		headerSize := 8
		if protocol == 6 {
			headerSize = 20
		}
		packet := make([]byte, 20+headerSize+len(payload))
		packet[0] = 0x45
		packet[8] = 64
		packet[9] = protocol
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[12:16], src.To4())
		copy(packet[16:20], dst.To4())
		binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
		t := packet[20:]
		binary.BigEndian.PutUint16(t, uint16(sport))
		binary.BigEndian.PutUint16(t[2:], uint16(dport))
		if protocol == 6 {
			key, reverse := source.String()+">"+destination.String(), destination.String()+">"+source.String()
			binary.BigEndian.PutUint32(t[4:], c.sequence[key]+1)
			binary.BigEndian.PutUint32(t[8:], c.sequence[reverse]+1)
			c.sequence[key] += uint32(n)
			t[12] = 0x50
			t[13] = 0x18
			binary.BigEndian.PutUint16(t[14:], 65535)
		} else {
			binary.BigEndian.PutUint16(t[4:], uint16(len(t)))
		}
		copy(t[headerSize:], payload)
		pseudo := make([]byte, 12+len(t))
		copy(pseudo[:4], src.To4())
		copy(pseudo[4:8], dst.To4())
		pseudo[9] = protocol
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(t)))
		copy(pseudo[12:], t)
		checkOffset := 6
		if protocol == 6 {
			checkOffset = 16
		}
		binary.BigEndian.PutUint16(t[checkOffset:], checksum(pseudo))
		now := time.Now()
		record := []uint32{uint32(now.Unix()), uint32(now.Nanosecond() / 1000), uint32(len(packet)), uint32(len(packet))}
		if c.err = binary.Write(c.file, binary.LittleEndian, record); c.err != nil {
			return
		}
		_, c.err = c.file.Write(packet)
	}
}

func (c *packetCapture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.file.Close(); c.err == nil {
		c.err = err
	}
	return c.err
}

type capturedTCP struct {
	net.Conn
	capture *packetCapture
}

func (c *capturedTCP) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.capture.write(6, c.RemoteAddr(), c.LocalAddr(), b[:n])
	return n, err
}
func (c *capturedTCP) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.capture.write(6, c.LocalAddr(), c.RemoteAddr(), b[:n])
	return n, err
}

type capturedUDP struct {
	net.PacketConn
	capture *packetCapture
}

func (c *capturedUDP) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if addr != nil {
		c.capture.write(17, addr, c.LocalAddr(), b[:n])
	}
	return n, addr, err
}
func (c *capturedUDP) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	c.capture.write(17, c.LocalAddr(), addr, b[:n])
	return n, err
}
func (c *capturedUDP) SetReadBuffer(n int) error { return c.PacketConn.(*net.UDPConn).SetReadBuffer(n) }
func (c *capturedUDP) SetWriteBuffer(n int) error {
	return c.PacketConn.(*net.UDPConn).SetWriteBuffer(n)
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(b)
}
