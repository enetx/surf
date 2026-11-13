# HTTP_1_1_REQUIRED wire check

The primary-source behavior and complete regression matrix are documented in
[the TCP ALPN audit](../tcp_alpn/README.md). `validation.json` is a sanitized
summary of a fresh, real Linux loopback pcap, independently decoded by
Wireshark 4.6.9 with the controlled server's TLS key log.

The Chrome-profile run sends one HTTP/2 GET, receives RST_STREAM error 13, and
closes that H2 session without sending GOAWAY. It then sends three HTTP/1 GETs:
the retry and one pooled request share a TLS connection; after closing idle
sockets, Preconnect prepares another HTTP/1 connection for the last request.
The captured ClientHellos advertise `h2,http/1.1`, then `http/1.1`, then
`http/1.1`. No ordinary H1 ALPN answer is used to seed the requirement cache.

The capture contains 52 packets and zero kernel drops. Linux loopback filter
statistics count both ingress and egress (104); the recorded pcap has one copy.
Assertions use the actual decoded packet streams. Raw pcap, private certificates,
key logs and unredacted decoder output remain outside the repository.

The regression cases were also run against unmodified Surf v1.0.237 using its
released HTTP dependency. They failed on the retained RST session, a processed
GOAWAY stream, simultaneous pending streams and idle Preconnect GOAWAY. The
updated implementation passes those same cases, plus the additional LRU,
isolation, header/body, override and ECH transition cases. An explicit 103
response still permits the peer-requested retry; final response headers expose
the body error without replaying the request. In a real ECH server handshake,
the cached HTTP/1 path retains ECH acceptance, certificate validation and the
HTTP/1 ALPN selection while using the normal owned session cache.

This is a controlled TLS-peer experiment, not a new native Chromium NIC
capture or a claim about browser TCP/IP timing. Surf's error-handling rules are
checked against pinned Chromium 158 source paths. The cache models one Surf
client network context; DOM top-frame NetworkAnonymizationKey partitioning and
full post-eviction browser socket-pool scheduling remain separate scopes.
