Wire fingerprint fixtures cover Chrome 156 on Windows and Android, and Chrome 157 on iOS.

The iOS reference is checked against Chrome 157.0.8103.37 on iOS 27.0.1.
The supplied navigation capture omits HTTP/2 PRIORITY and uses Russian; the
fixture retains its SNI, authority, path, language and 273-byte HEADERS block.
The wire test sets Russian explicitly; the profile's default remains English.
Saved-file requests use different headers and do not replace navigation.
The supplied TLS captures have no PSK and validate fresh handshakes only.

The TLS section records the normalized HTTP/2 ClientHello. GREASE code points,
key material and ECH payload bytes are normalized. Chromium extension order is
permuted; WebKit extension order is fixed. Empty extension bodies have no trailing spaces.

The HTTP/2 section records SETTINGS, WINDOW_UPDATE and the first navigation
HEADERS frame. HPACK representation annotations are omitted; field names, values,
order and frame parameters are retained. The ephemeral authority port is replaced
with PORT. These are expected client wire snapshots, not independent raw browser captures.

Header encoding and control frames have separate regression suites:
`tests/http2_browser_encoding_test.go` checks browser HPACK sensitivity and the
19/20-byte cookie-pair boundary, plus peer table growth beyond 4096 bytes;
`tests/tools/wirecapture/browser_sequence_test.go` replays eleven original
Chromium HPACK blocks byte for byte and checks Firefox's complete sequence,
including table shrink/growth, zero capacity and changed credentials;
`tests/http2_header_encoding_test.go` exercises
fluent overrides. `tests/http3_wire_test.go` checks browser-specific GREASE,
initial priority updates, cookie fields and custom frame factories. Codec-level
tests live in the HTTP and QUIC modules, including repeated fields, table updates,
eviction, name references, Huffman forms, bounded control queues and critical
stream failures. These source-derived checks do not upgrade the existing
navigation snapshots into independent raw-browser captures.

Encoding sources: Chrome 156.0.8078.79 pins Quiche commit
`a1628192cf32ba40d21e0dd80f485d68c24ff87a`; Firefox sources use
`FIREFOX_160_0_RELEASE`, including its vendored Neqo. Profile functions contain
direct links. For a browser update, recheck those rules against the new release
and capture actual browser traffic before changing reference fixtures.

Fresh 2026-11-09 Chromium/Firefox request sequences, including repeated and
changed peer table settings, credentials, QPACK instructions and control frames,
are preserved separately in [browser_sequences](browser_sequences/README.md).
That report distinguishes exact matches from measured encoding differences and
Wireshark decoding limits. [The capture tool](../../tools/wirecapture/README.md)
can reproduce the experiment; Go regression tests replay its browser inputs
offline. Existing navigation fixtures retain their original provenance.

Firefox 160 desktop uses a fresh browser capture from `tls.peet.ws/api/all` as its
reference. The installed browser runs on macOS with a Windows User-Agent override;
this does not establish a Windows kernel TCP fingerprint. SNI is retained for
tls.peet.ws, matching that capture.
ECH GREASE cipher selection, config IDs and ciphertext are connection-dependent.
The Firefox payload length is additionally checked against the captured 240 bytes.

## Firefox 160 verification

`firefox_160_sources.json` pins 29 inspected Firefox source files, including the
vendored NSS and Neqo implementations. The desktop profile and source links now
use Firefox 160; the `Firefox159()` selector and old navigation fixtures were
removed. Earlier independently captured codec sequences retain their actual
browser version and provenance.

`firefox_160_endpoint.json` records matching normalized TLS, complete HTTP/2
frames and ordered headers from direct browser and Surf visits to
`https://tls.peet.ws/api/all`. A second fresh browser profile produced the same
stable fields. `firefox_160_http1.json` preserves an independent HTTP/1.1 browser
reference and a normalized ClientHello. It verifies the HTTP/1.1-only ALPN and
Connection position; TE is an HTTP/2 default and is not inherited by HTTP/1.1.
User overrides, empty-value suppression, plaintext HTTP, forced HTTP/1.1, ALPN
fallback and RST_STREAM / GOAWAY HTTP_1_1_REQUIRED fallback are tested.

`firefox_160_audit.json` records six additional local header scenarios: HTTP/2
capacity 4096 and HTTP/3 capacities 0, 128, 4096, 65536 and 131072. All 66 aligned
browser/Surf exact-input header blocks match byte for byte. Wireshark decoded
181 of 198 total client sections; the 17 undecoded sections are retained as
decoder limits, rather than counted as independent decoded matches. All 18
Firefox 160 upload DATA-boundary vectors match and were independently decoded.

The DNS QUIC ClientHello uses a 240-byte ECH GREASE ciphertext; IP endpoints omit
SNI and use 208 bytes. The profile computes this from NSS's inner-message sizing
rules, including the actual PSK on resumed handshakes. The legacy min_ack_delay
parameter precedes max_datagram_frame_size in the captured Firefox 160 order.
Multipart boundaries use Firefox's current `----geckoformboundary` prefix and
two unpadded hexadecimal random uint64 values.

Firefox 160 still races TCP after the first UDP loss: this capture completed two
HTTP/1.1 and nine HTTP/3 requests, with the first TCP ClientHello observed 101 ms
after the first UDP Initial. Both Surf replays completed eleven HTTP/3 requests.
Delay/jitter/reordering captures also completed with no emulator queue overflow.
These observations do not establish equal fallback racing or congestion recovery.

## HTTP/3 references

`chrome_157_http3.json` contains a fresh Google Chrome 157.0.8103.51 reference
from an ordinary visible browser with public TLS verification and standard
Alt-Svc discovery. `firefox_160_http3.json` retains the independent Firefox 160
reference. Neither is generated by Surf. GREASE entropy, keys and CIDs are
normalized. Chrome Android shares Chromium QUIC policy; no fresh Android-device
capture is claimed. iOS/WebKit and Firefox mobile retain their independent
platform transport defaults. Older protocol corpora below retain their actual
capture versions as historical codec/recovery evidence, not selectable profiles.

`tests/http3_browser_test.go` checks real request headers and ordered SETTINGS,
decrypts Surf's Initial packets independently using RFC 9001 keys, reassembles
CRYPTO frames and compares cipher suites, groups, signatures, versions, key-share
lengths, ALPN, ECH shape and extension bytes with these browser references.
Chrome's parameter order and reserved parameters are freshly randomized. Firefox's
order is fixed; its initial packet number uses Neqo's distribution rather than
hardcoding the observed 13. The distribution is sourced from official
[Neqo v0.31.1 crypto.rs](https://github.com/mozilla/neqo/blob/v0.31.1/neqo-transport/src/crypto.rs).

Chrome matches the captured normalized HTTP/3 PERK and TLS JA3n. Firefox matches
TLS JA3n, SETTINGS, per-direction windows, CID length, ACK delay, datagram limit,
parameter order and modern reliable-reset advertisement. The older Surf captures
omitted compatible v1/v2 negotiation. Current Firefox profiles advertise it after
the fork's RFC 9368/9369 implementation and verification, described below.

The endpoint labels Firefox's `0xff02de1a` parameter as GREASE because the ID is
27 modulo 31. In [Neqo's transport-parameter source](https://github.com/mozilla/neqo/blob/v0.31.1/neqo-transport/src/tparams.rs)
it is actually legacy `min_ack_delay`; bytes `43e8` encode 1000 microseconds.
The native transport's newer ACK_FREQUENCY parser remains disabled. The fork now
has a separate opt-in legacy receiver: three varints followed by a single-byte
ignore_order flag, rather than the newer reordering-threshold varint. Firefox's
profile advertises the implemented receiver with a 1000-microsecond minimum;
Chrome does not. The Initial decoder checks the actual parameter and its order.
`LegacyAckFrequency(0)` disables both advertisement and frame handling. Outgoing
adaptive requests for the peer's ACK rate are not implemented by this mode.

Firefox's browser capture forced an Alt-Svc mapping and therefore included
`alt-used`. The Firefox desktop impersonation profile automatically supplies this
header from the current HTTP/3 destination authority in its captured position.
Port 443 is omitted; non-default ports are retained. Explicit headers take
precedence, and `HTTP3Settings().AltUsed(false)` disables the emulation. The
header is applied to a private HTTP/3 attempt and is not inherited by automatic
HTTP/1/2 fallback. Wire tests also cover POST, profile replacement, opt-out,
explicit values and reuse across destinations. ECH cipher choice can vary
between AES and ChaCha; the observed Firefox ciphertext length stays 240 bytes.

`tests/http3_config_test.go` uses a local bare QUIC/HTTP/3 peer to decode transport
parameters, inspect local priorities via qlog and test CID reuse, datagrams,
SOCKS5 UDP and explicit v2. `tests/http3_handshake_test.go` also covers explicit
TLS templates, snapshot isolation, errors, custom Initial packet numbers/IDs,
scrambling, real session tickets and reconnection/resumption. Public adapter tests
live in `tests/quictls/` and cover verification and session event metadata.

The fork now decodes dynamic QPACK according to the advertised receive settings;
warmed Firefox responses no longer fail on nonzero Required Insert Count.
The QUIC module tests cover RFC vectors, blocking/cancellation/deadlines, decoded
size limits, fragmented streams, critical-stream errors and client/server traffic.
The outbound encoder now uses dynamic tables with profile-selected insertion,
Huffman, Base and draining policies. See the [QPACK audit](qpack/README.md).
ACK timing/distributions, packet scheduling/coalescing, congestion/loss and
resource-specific priority behavior are not complete browser replicas. A matching
normalized fingerprint does not establish those behaviors.

QPACK stream policy is separately selected in Surf's browser profiles and tested
against local protocol peers. Chromium's QUICHE reserves decoder then encoder
streams, while `QpackSendStream` writes its type on the first instruction;
`QpackEncoder::SetDynamicTableCapacity` queues its instruction without flushing.
See [session initialization](https://github.com/google/quiche/blob/main/quiche/quic/core/http/quic_spdy_session.cc),
[stream writes](https://github.com/google/quiche/blob/main/quiche/quic/core/qpack/qpack_send_stream.cc)
and [capacity/flush behavior](https://github.com/google/quiche/blob/main/quiche/quic/core/qpack/qpack_encoder.cc).
Neqo reserves encoder then decoder streams and sends their types during HTTP/3
initialization; capacity changes are sent from its encoder update loop. See
[Neqo v0.31.1 connection setup](https://github.com/mozilla/neqo/blob/v0.31.1/neqo-http3/src/connection.rs)
and [encoder updates](https://github.com/mozilla/neqo/blob/v0.31.1/neqo-qpack/src/encoder.rs).
Surf implements startup and compression choices with builder overrides. The
original navigation fixtures do not record all QPACK streams or scheduling.
Separate [QPACK captures](qpack/README.md) compare actual field sections and encoder
instructions at capacities 0, 128, 4096 and 65536; they do not establish identical
instruction timing or QUIC packet scheduling.

`tests/http3_qpack_test.go` checks actual stream types/IDs and capacity instructions
from Surf, input/build snapshots, independent send/receive capacities and invalid
builder settings. The QUIC module's `tests/http3/qpack_client_test.go` covers both
orders, eager/lazy types, immediate/deferred announcements, absent/zero/smaller/
larger peer limits, constrained stream credit, STOP_SENDING and dynamic responses.

Surf imports HTTP/3 from the local `enetx/quic-go` fork based on official v0.65.0.
The fork contains generic controls without browser templates or uTLS dependencies.
Surf uses a small TLS event adapter with the [minimal uTLS fork](https://github.com/enetx/utls).
The fork provides a generic real-ECH inner layout callback; browser policies live
in Surf. See [ECH references](ech/README.md) for native captures, source checks,
private PSK resumption, authenticated retry and optional early data.
Dynamic `GetClientCertificate` is rejected for custom QUIC templates;
static certificates work. Standard-library ConnectionState snapshots cannot carry
uTLS's private TLS exporter closure. The default standard TLS path is unchanged.
Initial SETTINGS are queued before request headers; a local packet trace checks
the first transmitted stream as well as HTTP/3 frame creation order. This removes
the goroutine race that let a first-request snapshot omit SETTINGS. Independent
QUIC streams still do not promise delivery order under packet loss.
External endpoint checks are manual, reject protocol fallback and are not required
by CI. Saved browser fixtures keep these regression tests offline and repeatable.

The [HTTP/3 body and priority report](http3_behavior/README.md) records repeated
Chrome/Firefox upload captures and the resolved Firefox first-frame difference.
Its DATA/control-frame observations are independently checked with Wireshark.
The same report documents optional 0-RTT with standard TLS and browser templates,
including ECH; native browser resumption parity is still separate verification work.

## Transport capture audit

`transport_behavior.json` records actual browser/Surf captures before the changes
and two independent repeats after receive-window changes, followed by two repeats
with the final packet policies. Each scenario downloads 10 MiB over HTTP/2 and
HTTP/3 on the same local peer. Original pcap hashes and browser versions are
preserved; raw pcaps, TLS keys and temporary profiles stay outside Git.

Chrome now uses packet-local and multi-packet
[QUICHE Chaos Protection](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_chaos_protector.cc),
with a short prefix and trailing ClientHello bytes in the first packet following
[MultiPacketChaosProtect](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_packet_creator.cc).
It spends existing padding on CRYPTO splits/PINGs and frame shuffling. The fragment
count is variable. Firefox retains its observed sequential CRYPTO behavior.
Recovery tests reconstruct every byte and retain native fragment loss handlers.

Chrome selects an eight-byte Initial DCID, following Chromium's
[session pool](https://github.com/chromium/chromium/blob/156.0.8078.79/net/quic/quic_session_pool.cc)
and [default ID length](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_connection_id.h).
Firefox uses [Neqo's biased 8..20-byte distribution](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/cid.rs),
where eight occurs for 144 of the 256 random byte inputs. An exhaustive offline
test checks the distribution. SCID selection remains independent.

Chrome omits an ACK-only Initial when Handshake data is ready. Initial key disposal
remains in the native sent-packet path. Firefox retains Initial+Handshake and uses
[Neqo's starting path MTU](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/pmtud.rs):
1252-byte IPv4 / 1232-byte IPv6 UDP payloads. Actual destination address selection
happens at dial time, including SOCKS5 destinations.

HTTP/2 receive-credit batching follows Chromium's
[half-window and elapsed-time predicates](https://github.com/chromium/chromium/blob/156.0.8078.79/net/spdy/spdy_stream.cc).
Firefox uses its [4 MiB / 96 KiB emergency predicates](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Session.h)
and [initial per-stream increase](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2StreamBase.cpp)
from the 128 KiB push allowance to the 12 MiB pull window. Go retains normal body
reader backpressure. A raw TLS-peer regression observes initial WINDOW_UPDATE
frames and batching on a response exceeding the stream window.

Chrome's QUIC credit updates use
[QUICHE's half-window threshold](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_flow_controller.cc);
Firefox uses [Neqo's quarter-window threshold](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/fc.rs).
Chrome also follows [OnAckNeedsRetransmittableFrame](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_session.cc):
repeat current MAX_DATA after 19 ACK-only packets instead of inserting a periodic
PING. This repeats existing credit without growing the window. A real two-MiB
transfer tests the policy, explicit override and unchanged probe credit.

Encoded packet-number lengths follow
[QUICHE's outstanding-range / congestion-window calculation](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_packet_creator.cc)
and [Neqo's pre-ACK / post-ACK calculation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs).
The QUIC engine enforces safe lower bounds independently. Regression tests include
one-byte rollover and reconstruction of actual Initial packet numbers across 255
and 65535; the independent decoder reconstructs the full number before nonce use.

Firefox's ACK-only PING policy follows
[Neqo recovery](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs):
at least 16 tracked sends and strictly more than two PTOs since an eliciting send,
or at least 200 and strictly more than one PTO. These are send-time decisions;
there is no synthetic timer or fixed PING count. Deterministic boundary tests
supplement live captures. Recovery history and PTO estimation remain quic-go's.

Both profiles retain the active connection ID on an unchanged path, following
[QUICHE's peer-ID manager](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_connection_id_manager.cc)
and [Neqo paths](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/path.rs).
Peer retirement and migration still select replacements. Chrome stages SETTINGS
and initial control GREASE before releasing the handshake, matching
[SendInitialData](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/quic_spdy_session.cc).
When peer credit is insufficient, an asynchronous write continues on the same
control stream. Tests cover backpressure, cancellation, factories, custom dialers,
callback composition and accepted/rejected early data.

Chrome's first 1-RTT packet carries ACK and control-stream bytes; its datagram
length varies with GREASE and ACK ranges. Chrome may coalesce an Initial ACK
depending on handshake scheduling. Firefox's client now sends an Initial+Handshake
ACK prefix before Finished, with a zero tail outside the long-header packets,
matching the observed Neqo flight composition. The following Finished flight is
Handshake+1-RTT and has no Initial size padding.

`InitialPaddingMode(InitialPaddingDatagram)` and `HandshakeAckBeforeData(true)`
select this behavior independently. When a short-header packet is coalesced with
Initial, padding is encrypted inside that last packet to preserve AEAD. Native
Initial key disposal, certificate verification and PTO recovery are retained.
Surf does not reproduce NSS's asynchronous certificate-verification latency.
The matching source is [Neqo output_dgram_on_path / pad_initial](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs).
The dissector calls external tails `(Random) padding`; raw byte inspection showed
zero-filled tails in these captures, not random bytes.

Firefox also uses `SortConnectionIDFrames(true)` to retain increasing sequence
numbers through both queue admission and serialization, following
[ConnectionIdManager::write_frames](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/cid.rs).
Native Go frame shuffling otherwise changes their order. Handler association is
preserved, including in recovery tests. At the time of these captures packet-number generation was shared. Current
Firefox allocation is described in the transport update below; these historical
captures do not establish an exact reproduction of recovery or probe timing.

The earlier `packet-policies-*` repeats, before handshake-flight staging, observed:

| Observation | Chromium / Firefox | Surf preset / exact request replay |
| --- | --- | --- |
| Chrome first application packet | ACK + control STREAM, 1-byte PN | Same frame types, stream ID and PN length |
| Firefox first application packet | ACK + three NEW_CONNECTION_ID frames | Same frame types and PN length; no unsolicited RETIRE |
| Chrome HTTP/2 WINDOW_UPDATE count, 10 MiB | 5 | 5 / 5 |
| Firefox HTTP/2 WINDOW_UPDATE count, 10 MiB | 16 | 16 / 16 |
| Chrome HTTP/3 stream-credit updates | 3 | 3 / 3 |
| Firefox ACK-only PING count | 3 in each final repeat | 3 / 3 in each final repeat |
| Firefox Finished datagram | 169 bytes, after a separate padded ACK | 1252 bytes, coalesced Initial ACK; remaining difference |

The equal final PING counts are observations, not invariants: earlier repeats
observed 4 or 9 browser probes and 3 or 5 Surf probes. Browser timing, packet
coalescing and the native recovery implementation affect the decision snapshots.
Chrome's Finished datagrams measured 142/143 bytes in the two final browser runs
versus 146..148 for Surf; GREASE payloads and ACK encoding/scheduling vary.
The later `handshake-policies-*` repeats additionally cover peer QPACK capacities
0 and 65536. They retain encoded sizes, ACK delay fields, control SETTINGS/GREASE
sizes, zero/nonzero tail counts and NEW_CONNECTION_ID sequence order.
All historical pcaps were reanalyzed with the corrected parser; the fixture's
schema 2 distinguishes first Handshake, Finished and external padding. No
1-RTT packets or packet-number lengths in these captures remained undecoded.

Initial keys can be derived by an observer; see
[RFC 9001, section 5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2).
Later encrypted frame contents require endpoint visibility or session keys.
Encrypted record/datagram lengths alone do not uniquely prove the frame types.

Chrome's remaining small size variation is expected from
[uint32 SETTINGS GREASE](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/quic_send_control_stream.cc)
and [reserved-frame serialization](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/http_encoder.cc).
A captured pair differed by six bytes: four bytes from a GREASE value encoded
with eight bytes rather than four, and two reserved-frame payload bytes. Known
SETTINGS were identical. The independent decoder has these captured prefixes as
regressions; the implementation does not force random packet sizes to match one
browser draw. ACK delay and encoded packet-number width can also change length.

The final handshake repeats measured Firefox ACK prefixes of 1252 bytes with
1175 zero tail bytes in the observed four-byte server-DCID / three-byte client-SCID
case. Browser and Surf both sent Initial ACK + Handshake ACK, followed by a
Handshake CRYPTO + 1-RTT ACK/NEW_CONNECTION_ID flight with sequence numbers 1,2,3.
Finished datagrams were 169 bytes for Firefox and 168..170 for Surf. Subtracting
extra ACK-delay varint bytes and encoded packet-number bytes yields 168 for every captured case.
The remaining differences reflect real ACK delay and quic-go's shared packet-number
generator; no artificial delay or unsafe truncation was added to force 169.

Chrome Finished datagrams varied from 142..149 bytes in these browser captures
and 143..149 for Surf. Subtracting the actual control-stream prefix and extra
ACK-delay/packet-number bytes yields 103 for every case. The
`finished_size_breakdown` records the calculation. Thus the observed size variation
is explained by actual GREASE/control bytes and numeric encodings rather than an
unexplained fixed payload overhead. This is a result for these captures, not a
claim that every network path, retry or loss scenario has browser-identical timing.

HTTP/2 remained at five WINDOW_UPDATE frames for Chrome and Surf. Firefox emitted
15 or 16 across the final repeats, while Surf emitted 16; batching predicates are
unchanged, and boundary counts depend on the read/close schedule. Firefox PING
counts also varied with load (3..8 browser, 3..13 Surf in the final scenarios).
The timing policy remains source-based, not a fixed target count.

## Delay and loss audit

`network_behavior.json` contains sanitized 2 MiB response observations from
Chromium 156.0.8078.79, Firefox 159.0.1 and the corresponding Surf presets/exact
input replays. Private packet captures are identified by SHA-256. The socket
emulator adds 10 ms per direction and, in two runs, drops every 37th datagram per
remote/direction. Queues reported no overflow or I/O/logging errors.

Without loss, late ACK medians were 10 for Chrome and 2 for Firefox, matching
both Surf replays, including with added delay. Early ACK counts vary with
piggybacking/timers. With periodic loss, all browser and Surf sequences completed,
but Chrome late medians were 3 then 2 versus Surf 4/5 then 4/3. Firefox opened a
second QUIC connection in both browser runs; Surf used one. Late Firefox medians
were 3 then 2 versus Surf 2 in both runs. These differences are retained; equal
threshold policies do not establish equal congestion/loss-recovery behavior.
ACK bookkeeping is per connection, even when wire packet numbers are reused.

Dropping the first incoming and first outgoing datagram still allowed Chromium
and both Surf replays to finish. Firefox instead attempted HTTP/1.1 over TCP at
about 100 ms in the earlier repeated capture. The test peer supports HTTP/2 only,
so navigation failed with `NS_ERROR_NET_RESET` before a complete H3 sequence.
A further diagnostics run reproduced the failure and retained browser metadata,
peer status and the capture. It is explicitly marked incomplete in the fixture;
no successful Firefox/Surf parity is claimed for this case.

These are application-level UDP captures with synthetic IP envelopes, not NIC
or kernel-network emulation. Capture-point details are in the tool README.
These captures predate configured congestion control, fallback racing and
Firefox per-space packet numbers. Current mechanisms use separate histories and
an internal congestion transmission sequence; historical packet sizes and timing
are retained here as observations of the recorded revision.

HTTP/3 SETTINGS GREASE is now drawn per connection. Chromium uses independent
uint32 draws for the reserved identifier and value, following
[QuicSendControlStream::MaybeSendSettingsFrame](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/quic_send_control_stream.cc).
A `GreaseFactory` builder override changes this generation without changing
stable SETTINGS, QPACK limits or other profile choices. Wire tests verify new
connections, request reuse, error propagation and configured-input immutability.

## Completed fallback and variable-delay experiments

`fallback_behavior.json` records independently checked HTTP/1 requests after
adding HTTP/1.1 to the capture peer. In two Firefox repeats with 10 ms one-way
UDP delay and the first datagram dropped in each direction, the browser completed
2 requests over HTTP/1.1 and 9 over HTTP/3, across two TCP connections and one
QUIC connection. Both Surf replays completed all 11 over HTTP/3 on one connection.
The first TCP TLS ClientHello appeared 101 ms after the first UDP Initial in
both browser repeats. This is server socket observation, not TCP SYN or NIC timing.
Chromium and its Surf replays completed all requests over HTTP/3 in this scenario.
The older failed Firefox captures remain historical evidence of the peer's missing
HTTP/1 support; they are not reclassified as successful captures.

The mixed impairment run adds uniform deterministic jitter of +/-5 ms around
10 ms one-way delay, holds every 17th datagram for an additional 20 ms, and drops
every 37th datagram per remote/direction. All three client groups completed all 11
HTTP/3 requests for both browsers. The emulator recorded out-of-order deliveries,
zero queue overflow and no I/O/logging errors. Firefox opened two QUIC connections;
Surf used one. `network_jitter_ack_observations.json` preserves measured ACK
histograms; successful transfers do not establish equal recovery or pacing.

The browser peer does not advertise legacy min_ack_delay or send ACK_FREQUENCY
requests. These captures validate baseline ACKs and the client advertisement,
not browser/Surf equality after a peer-requested ACK-rate update. The new receiver
is separately checked against an independent Neqo wire vector, deterministic
sequence/timer/reordering tests and real QUIC connections that inject updates.
Equal sequence numbers are accepted, older updates ignored, and existing timers
are retained, following the pinned Firefox tracking.rs. Delay below the advertised
minimum closes the connection; malformed or unnegotiated frames are rejected.
These historical captures predate the outgoing sender described below.
These captures predate connection racing and RFC 9368 support described below.
Firefox per-space allocation is now implemented; see the transport update below.

## Cross-protocol fallback and remaining transport work

HTTP/3 fallback now uses the same JA transport as ordinary TCP requests, retaining
the selected ClientHello, HTTP/2 header policy and stream settings. Protocol-aware
profiles defer their default pseudo-header order until the actual attempt:
Firefox uses `:method,:path,:authority,:scheme` over HTTP/2 and
`:method,:scheme,:authority,:path` over HTTP/3. Explicit request metadata wins.
The private attempt does not overwrite the caller's headers. Closing the HTTP/3
client also closes idle TCP fallback connections.

Regression tests observe decrypted HTTP/2 frames after an HTTP CONNECT proxy or
a QUIC handshake timeout, compare the TCP ClientHello with the independent
Firefox 160 reference, and check GET/POST bodies, overrides, protocol defaults,
profile replacement and cleanup. Native HTTP/3 and HTTP/3 -> HTTP/1.1 are checked
separately. This repairs sequential fallback; it does not add connection racing.

Firefox's outgoing legacy ACK_FREQUENCY policy is now implemented.
[Neqo's controller](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/ackrate.rs)
selects its target from congestion window, packet size and RTT only when the peer
advertises legacy min_ack_delay. Its
[default ratio](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/params.rs)
targets four acknowledgments per RTT, with packet tolerance bounded to 2..256 and
delay bounded by the peer minimum and 50 ms. It keeps one request outstanding,
tracks ACK/loss, and updates the effective peer ACK delay used by recovery.
The implementation includes negotiated peer parameters, live policy inputs, frame
lifecycle handling and PTO tests.
Browser defaults belong in Surf and generic mechanics in the existing QUIC fork.

Chromium 156's pinned QUICHE revision still has the peer-minimum setup marked TODO
in [SetFromConfig](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_sent_packet_manager.cc).
The sender minimum remains infinite, so its outgoing ACK_FREQUENCY path stays
disabled in that source baseline. The Firefox legacy sender should not be enabled
in the Chrome profile.

`firefox_160_ack_frequency.json` records five new captures with the server's
legacy minimum set to 1000us: two 2 MiB response runs at 10 ms one-way delay, two upload
sequences with +/-5 ms jitter, every 17th datagram delayed and every 37th dropped
(QPACK capacities 0 and 65536), and a Chromium control. Every group completed all
11 HTTP/3 requests. Wireshark independently decodes every received request and
matches its connection, sequence, tolerance, delay and ignore_order to server
qlog. Frames seen at the capture socket but dropped before the server are retained
separately; connection attribution uses original DCIDs, not reused UDP ports.

The undisturbed Firefox first request is sequence 0, tolerance 2, ignore_order=false
in all groups. Measured requested delays are 5867us in Firefox, 5657us in the Surf
profile and 5758us with exact-input replay. Firefox's initial window is 10 datagrams
for the profile's MTU, following
[classic_cc.rs](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/cc/classic_cc.rs).
Native quic-go's 32-datagram window produced tolerance 8 in an earlier exploratory
run; the exposed initial-window control fixes that first-request discrepancy.
Both Chromium and its replays send zero ACK_FREQUENCY requests.

The second bulk-response run uses the published QUIC v1.0.9 module with the
workspace disabled. Its first request again has sequence 0, tolerance 2 and
ignore_order=false in every group (5649us, 5314us and 5143us respectively).
An earlier repeat timed out in Firefox's automation session setup before any
network requests; it is not counted as a successful capture.

Later tolerances and update counts in impaired transfers differ: the formula is
the Firefox policy, but its inputs come from independent RTT measurements and
native quic-go congestion/recovery/pacing. Firefox also opened two connections in
one run. These captures establish negotiation and adaptive frame behavior, not
complete packet-stream equivalence. Captures ran on macOS; the Firefox Windows
User-Agent override does not emulate Windows networking. The engine additionally
retains a conservative PTO delay bound for lost-but-unconfirmed requests until
the latest request is acknowledged, protecting against late delivery/feedback.

The new analyzer filters Wireshark output to Initial and ACK_FREQUENCY packets.
The generic runner now rejects subprocess buffer errors even when termination
reports exit status zero; large full decodes can exceed its 64 MiB buffer. Raw
PCAP and key material remain private, and this report was generated from fresh
filtered decodes, independently of those large full-output JSON files.

Connection racing is now available explicitly through
`HTTP3Settings().ConnectionRacing(true)`. The selector prepares pooled connections,
then gives the application request to exactly one normal transport. It does not
race two HTTP requests. Firefox's
[backup timer](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp)
and [preferences](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/modules/libpref/init/StaticPrefList.yaml)
use 100 ms in the applicable pending-transaction path; HTTPS DNS records and Happy
Eyeballs use other paths. Chromium's
[waiting-job policy](https://github.com/chromium/chromium/blob/156.0.8078.79/net/quic/quic_session_pool.cc)
depends on network history, brokenness and cached RTT. Competing connection
attempts share preparation per origin. A TCP winner can leave QUIC warming in the
background; a later request uses the prepared QUIC pool. External tests cover
non-replayable streams, factories, cancellation, proxies and cleanup, while private
selector tests inspect coalescing and bounded history. Delay policy is in the
profile, with a fixed-delay override and an application callback in the builder.
Chrome's observations are per origin/client and do not implement the browser's
full persisted network state or DNS scheduler. The transport update below adds
client-scoped Alt-Svc/HTTPS discovery and profile backoff policies.

## Ordinary browser references for connection-racing work

`connection_racing_native_firefox_160.json` and
`connection_racing_native_chromium_156.json` use new visible browser profiles and
public TLS at `https://fp.impersonate.pro/api/http3`. Both selected HTTP/3 on their
second ordinary navigation after Alt-Svc discovery. There was no forced protocol,
headless mode, User-Agent override, certificate bypass or resolver/proxy override.
Only profile isolation, automation and startup/JSON-viewer UI controls were used.
This is an endpoint fingerprint comparison, not a packet capture under controlled
loss or a measurement of browser connection-racing timers.

Both controls match Surf's JA3n, stable ordered HTTP/3 SETTINGS, header order and
client CID length. Firefox's complete request headers and TP order also match.
The Surf responses recorded in that historical comparison omit QUIC v2; current
RFC 9368 validation results are recorded below. Chromium's stable TP
values match; its TP order and GREASE vary. The installed browser is Chromium,
so its Sec-CH-UA lacks the Google Chrome brand present in Surf's Chrome profile.
The analyzer retains these differences instead of turning them into a full-match
claim. Raw JA3 extension order is randomized; matching JA3n does not imply an
identical ordered ClientHello on every connection.

Earlier local timer observations used browser test preferences and trust overrides.
They are diagnostics and cannot establish ordinary browser behavior. Firefox's
forced Alt-Svc preference sets NS_HTTP_DISALLOW_SPDY in
[nsHttpChannel.cpp](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpChannel.cpp),
which explains the HTTP/1-only fallback seen there. Ordinary ALPN setup is in
[TlsHandshaker.cpp](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/TlsHandshaker.cpp).
Chromium's
[proof verifier](https://github.com/chromium/chromium/blob/156.0.8078.79/net/quic/crypto/proof_verifier_chromium.cc)
also rejects otherwise accepted QUIC chains with unknown roots unless explicitly
allowed. A controlled, publicly trusted peer is unavailable in this environment.
Normal-browser loss/racing parity remains unverified; the timer policy is pinned
to source and the implementation is covered by offline transport tests.
`connection_racing_sources.json` hashes the inspected source files.

[RFC 9368](https://www.rfc-editor.org/rfc/rfc9368.html) is a larger engine change:
v1 and v2 support individually is insufficient for switching within a handshake.
The implementation and its validation are now recorded in the section below.
Per-space packet-number allocation additionally affects shared recovery and
congestion histories; the transport update below now records its implementation.

## Congestion controller source verification

Firefox 160 selects CUBIC (`network.http.http3.cc_algorithm=1`) and classic
slow start (`slow_start_algorithm=0`). Its profile now selects RFC 9438's curve,
whole-segment ACK credit and byte-based slow start with 10 initial MTU segments.
Chromium 156's external QUICHE defaults select byte-mode CUBIC, original HyStart,
32 initial 1460-byte accounting segments and two emulated connections; those
segments are independent of its UDP MTU. BBR external defaults are false at the
pinned revision. Profile comments link the exact preference, flags, sender and
constant definitions. User overrides use the same fluent API.

The QUIC module tests 1120 vectors generated by compiling the original Neqo Rust
controller and 540 vectors from the original QUICHE C++ controller. They cover
concave/convex growth, Reno-friendly regions, different MTUs, ACK sizes, idle
periods, loss/ECN and undo. Separate tests cover ACK batching, send-time utilization,
slow-start exits, state snapshots, validation and migration. These are source-derived
arithmetic references. Existing public-browser captures continue to establish only
their recorded handshake/header fields; they do not establish equal pacing, PRR,
loss recovery, persistent congestion, connection racing or browser experiments.

## RFC 9368 / RFC 9369 client verification

Firefox's fluent profile enables compatible negotiation and supports both v1 and
v2. Its first flight remains v1; `version_information` now lists GREASE, v2, v1.
Native clients and server negotiation policy keep their previous defaults.
The engine validates the selected version against authenticated server information
and prevents induced downgrades. Retry uses the original version; Initial PN space
and TLS transcript survive the switch; Handshake and 1-RTT use negotiated labels.
Original-version 0-RTT retains its packet type and key labels. Session tickets and
NEW_TOKEN caches are scoped to their versions. Browser-history selection of the
next original version is separate work. Surf now supports custom-template early
data, including ECH; see the [ECH report](ech/README.md). Native browser resumption
and 0-RTT parity remain separate verification work. Generic version/0-RTT checks
do not establish complete browser behavior.

The fork's UDP integration tests exercise actual Dial and client Finished in both
directions, Retry, original-version ACKs, reordered Handshake, lost server flight,
corrupted candidate Initial, old servers, classic VN and VN followed by a compatible
switch. Contradictory or missing authenticated information and forged VN are rejected.
Codec, TLS keys, session-cache isolation, original-version 0-RTT headers and scalar
configuration snapshots have additional tests. Surf's independent UDP decoder now
handles RFC 9369's salt, key labels and Initial packet type, and tests both original
versions. The existing connection-racing test now gives successful QUIC a policy
head start; a deliberate zero-delay tie between two warm pools has no fixed winner.

Independent manual HTTP/3 checks use official aioquic 1.3.0 with a private test CA
explicitly trusted by the Go clients, without certificate bypass. Both compatible
directions and Retry complete. A three-connection standard-TLS sequence obtains a
v1 ticket, resumes with v1 0-RTT while switching to v2, then resumes v2 directly with
v2 0-RTT. The symmetric v2-to-v1 resumption sequence also passes. The peer
independently confirms resumption and early-data acceptance;
client qlog confirms packet versions. This is interoperability evidence, not an
ordinary-browser packet-loss capture or a complete congestion/pacing parity claim.

`firefox_160_rfc9368_endpoint.json` preserves fresh ordinary Firefox 160 and
Surf endpoint comparisons, with private network identifiers omitted. Native browser
Alt-Svc discovery selected HTTP/3 on the second navigation. The primary Surf
follow-up explicitly enables SecureTLS. Raw PERK text and hash agree:
`4678782326c9f141e5fa97242ba044d3`. The initial pair also agrees on the normalized
hash `56c5da8e647c74b80c8231fa9e86c948`; the verified follow-up instead returns
`a7c88866b460a05ed7bdbc492f457376` while retaining the same raw PERK and parsed
version-information list. In those responses the endpoint places GREASE before
or after v2 in its normalized list. Keep this variation verbatim rather than
biasing the browser's GREASE distribution to force one normalized hash.
The browser runs on macOS and Surf uses the Windows profile; this artifact makes
no Windows kernel claim. `rfc9368_interop.json` records the independent local
implementation results above.

## Send scheduling and discovery update (2026-11-11)

`browser_transport_2026_11_11.json` records fresh ordinary Firefox 160 and Chromium
156 navigation on the publicly trusted endpoint and verified Surf Windows
requests. TLS JA3n, SCID length, ordered HTTP/3 settings, header order and transport
parameter values agree. Firefox parameter order agrees as well; Chromium order
is independently randomized. Header values retain the real macOS/Windows and
Chromium/Google Chrome brand differences. The report never erases those fields
to manufacture equality. Raw response hashes retain provenance without storing
TLS secrets or browser profiles.

The QUIC fork now supplies configurable congestion-window ceilings, leaky-bucket
and scheduled pacing, PRR, bounded immediate recovery sends and persistent-loss
detection. All browser choices live in Surf's fluent profile chains. Chromium
selects its 2000 × 1460-byte ceiling, scheduled bursts and PRR; Firefox selects
two-packet pacing with signed debt, classic recovery and a three-PTO persistent
congestion threshold. The fixed engine CWND ceiling is removed for Firefox;
native history/memory and integer safety limits remain. The source arithmetic
fixtures add 120 original Neqo pacing rows and 200 original QUICHE PRR comparisons.
The scheduled pacer also stops compensating for elapsed time during application
pauses, following its source application-limited notification.

Firefox now uses independent wire counters and histories for Initial, Handshake
and Application Data, and disables artificial random/PTO gaps. A separate
internal transmission sequence protects shared
congestion/recovery boundaries and spurious-loss undo. Chromium keeps the shared
wire counter used by its original packet creator. Tests cover rejected 0-RTT,
Retry, key disposal, skipped/unsent ACK rejection, migration and complete upload
plus echoed download under deterministic losses in both directions.

Surf adds client-scoped Alt-Svc and HTTPS DNS discovery, expiry/clear, origin TLS
verification at alternate addresses, profile broken-service policies, shared
DNS lookup cancellation and optional staggered address attempts. HTTPS records
use the configured DNS/DoT transport with system resolver addresses, or an
application callback; unsupported system DNS integration does not substitute a
public resolver. Alias chains, ALPN, mandatory keys, port, hints and ECH are
validated. Official TLS/uTLS APIs complete real ECH on QUIC and TCP; tests verify
that a rejected ECH attempt does not retry without it, including subsequent
requests during QUIC backoff. Binding TTL is independent of brokenness; a failed
refresh of an expired ECH binding fails closed. DNS TCP-only services retain
their target/port and original Host/SNI; `no-default-alpn` controls which
transports may participate. A public TLS-state adapter
lets the HTTP transports authenticate advertisements received through uTLS.
Automatic discovery retains plain HTTP, forced protocols and application-owned
transport policies. An unused automatic QUIC transport does not open a UDP socket.

The current Firefox release does not enable its Nightly Happy Eyeballs path by
default; configurable address staggering is therefore not blindly enabled in
every profile. Persisted browser network state, experiments, resource scheduling,
DNS integration beyond supported system/custom resolvers, kernel/NIC timing and
full browser resumption remain outside the verified scope. Ordinary public
endpoint requests do not prove identical congestion, pacing or loss timing;
those mechanisms are verified separately against source and controlled Go peers.

References are pinned in profile comments to Firefox `FIREFOX_160_0_RELEASE`,
Chromium `156.0.8078.79`, and QUICHE
`a1628192cf32ba40d21e0dd80f485d68c24ff87a`. See the QUIC module's `UPSTREAM.md`
and `internal/congestion/testdata/README.md` for update hooks and oracle runners.


## Chrome 157 audit (2026-11-11)

The active Chrome profiles and TLS helpers expose only version 157. The ordinary
reference browser is Google Chrome 157.0.8103.51. Chromium source links use that
tag; its DEPS pins QUICHE `541aa2a7889b7ea7651e41afc58211f2a256850a`.
`chrome_157_audit.json` contains sanitized comparisons, source URLs/hashes and
capture provenance. Full raw responses and NetLogs remain private.

`chrome-157-macos.golden` includes a newly captured ClientHello and the exact
first HTTP/2 HPACK block from tls.peet.ws. The offline peer reproduces the native
469-byte HEADERS frame and compares its 464-byte HPACK fragment byte for byte.
Windows changes only declared OS navigation fields and removes SNI for its
loopback peer. Android expectations are source-derived from the unchanged shared
TLS/H2 fields, not represented as a fresh Android-device capture.

Chrome HTTP/1 sends Connection after Host, lowercase Client Hints, and no default
Priority. Multiplexed requests add their own Priority after protocol selection.
The HTTP module's HeaderCaseKey is private metadata and is filtered centrally
from every protocol's validation/encoding. Explicit header values are preserved.

HTTP/3 can stage priority, HEADERS and bodyless FIN in one connection-loop turn.
Thirty consecutive wire tests require their coalescing with available credit;
blocked control streams are tested separately and cannot block request HEADERS.
Actual packet sizes, congestion and other active streams still apply. Browser
NetLog and QUIC qlog observations are not NIC packet captures.

A missing QPACK capacity setting and an explicit zero are distinct: Chromium
OnSetting queues a zero only for the latter. EncoderCapacityRequiresSetting and
EncoderZeroCapacity express these choices through the fluent profile.

Proxy tests verify real SOCKS UDP HTTP/3, explicit UDP refusal with HTTP/2 fallback,
HTTPS proxy fingerprint preservation, explicit proxy precedence over environment,
NO_PROXY, one selector evaluation per attempt, pool separation across routes,
immutable HTTP/2 settings and retained ECH. IPv6 is tested using verified TLS with
both native TLS and Chrome. ForceHTTP3 also registers its transport without a
separate settings call; it retains fallback when UDP is unavailable.
