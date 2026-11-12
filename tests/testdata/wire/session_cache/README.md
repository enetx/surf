# Browser session cache verification

The implementation uses `Builder.SessionCache()...Set()`, matching Surf's other
nested builders. There is no top-level Surf cache constructor. TCP, QUIC and
Both select subsequent settings; each protocol has independent owned state.
Profiles configure the same concrete fluent settings, and user overrides apply
last. An explicit application cache retains its policy. TCP uses a separate
`tcp:` key namespace, including native Go TLS and browser fingerprints.
The caller's TLS config remains the config exposed by GetTLSConfig.

## Source and deterministic checks

Sources are pinned in the profile code to Chromium 157.0.8103.51, its vendored
QUICHE 541aa2a7889b7ea7651e41afc58211f2a256850a, and Firefox 160.
Chrome QUIC keeps two newest tickets, single use, with whole-entry expiry.
Chrome TCP keeps two TLS 1.3 tickets, single use, and reusable TLS 1.2 state.
Its expired selected ticket causes one miss; an older live ticket remains for a
later lookup. Firefox keeps ten expiry-ordered tokens and consumes each selected
token. Equal-expiry new tokens go first; overflow removes the earliest token
before inserting the new one. Firefox's memory accounting differs; see the
[behavior inventory](../../../../BROWSER_PARITY.md).

Actual loopback TLS peers capture the three wire ClientHellos after stopping
new ticket issuance: both browser profiles offer PSK only on the second
connection. Separate actual QUIC TLS rejection tests verify that pending
ordinary PSKs survive while their early-data permission is cleared, with both
the native TLS engine and Chrome/Firefox templates. Public custom-cache tests
exercise native/TCP/QUIC ownership, shared cache namespaces, selected scopes,
explicit disabling, both TLSConfig/Session call orders, builder validation and
retention of the native TLS config pointer.

Queue fixtures begin with an actual TLS client session and use only public
serialization/accessors. Tests cover two/ten-ticket exhaustion and overflow,
ordering, expiry, legacy reuse, compatibility grouping, bounded eviction,
concurrent single consumption and non-consuming inspection. Version-selection
tests restore older queued tickets without a second PSK cache, retain original
configurations, and check disabled/disallowed/missing/expired cases.

## Fresh packet observations, 2026-11-12

`observations.json` stores sanitized metrics and capture/source hashes. Raw
captures, browser profiles, tickets and traffic keys stay private.

- The final Surf probe made three new connections for each combination of
  Chrome/Firefox and HTTP/2/HTTP/3. All 12 connections used certificate-verified
  accepted ECH; all eight repeated connections resumed. HTTP/3 probes enabled
  early data and ordinary protocol racing through the public builder. Its
  capture contains 339 packets, with zero kernel capture drops.
- An independent official aioquic 1.3.0 peer selected v2 from a Firefox v1-first
  connection, then accepted resumed v2 and 0-RTT twice. A 20 ms UDP egress delay
  ensured measured RTT. Recovery's initial qlog RTT was 100 ms cold, 24 ms on
  the first repeat and 20 ms on the second, exactly matching each previous
  ticket's measured RTT truncated to whole milliseconds. These initial values
  are taken from recovery initialization, before later ACK measurements; the
  application-ready callback already has a fresh measurement. That capture
  contains 44 packets with zero kernel drops. A private test CA was explicitly
  trusted; certificate checks remained enabled.
- Fresh ordinary Chrome 157 and Firefox 160 each completed three HTTP/3
  navigations with encrypted SNI using natural idle expiry and standard Secure
  DNS preferences. A new Chrome resumed ECH pair passed the original-transcript
  ECH acceptance/PSK verifier before redaction. The Firefox capture has 38 kernel
  drops and four UDP GSO aggregates; its analysis copy splits only exact
  1252-byte multiples. A resumed server PSK selection was visible, but a complete
  new resumed ECH transcript was not retained. Existing authenticated Firefox
  references remain authoritative for the previously verified stable inner.

Ordinary Chrome key logs also include TCP race candidates. A TCP ClientHello in
that log must not be compared with a QUIC reference by ordinal position alone;
select the actual wire connection and QUIC ALPN/transport parameters. Current
Surf Chrome and Firefox resumed QUIC stable inner shapes match the retained
native references. These checks do not establish identical native packet counts,
full browser resource scheduling, mobile behavior or loss/congestion timing.

The independent RTT observation measures Surf interoperability and restoration;
it is not a native Firefox packet-timing oracle. Full HTTP/3 application-state
compatibility, disk persistence, native mobile references and Firefox byte-based
memory eviction remain separately tracked open work.
