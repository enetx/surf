# Initial QUIC version from a resumable session

Firefox's profile enables `QUICSettings().ResumeVersion(true).Set()` through
the same public builder available to applications. A cold connection retains
the configured first version. A later connection can start with the version
associated with its available TLS ticket, including v2 after a compatible
v1-to-v2 switch. Chrome retains its configured version policy.

## Pinned browser sources

Firefox 160's vendored Neqo stores the negotiated version when
[creating a resumption token](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs#L649).
When [restoring that token](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs#L774),
it checks that the version is enabled, restores TLS and assigns the version
to both the connection and its initial-version configuration. The
[version configuration comments](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/version.rs#L152)
describe that resumption rule explicitly.
[RFC 9369 section 5](https://www.rfc-editor.org/rfc/rfc9369.html#section-5)
binds TLS resumption and address-validation tokens to the negotiated version.

This is session-dependent behavior. Merely completing an earlier connection
does not change a future connection's initial version without a usable ticket.

## Implementation and lifecycle

The QUIC fork exposes `quic.SessionVersion` to read its existing local TLS
session metadata. That block now uses revision 6 and includes the negotiated
version; revision 5 remains readable for resumption. The change preserves
application-owned `SessionState.Extra` entries and does not change the server's
ticket bytes. The uTLS fork adds a read-only `ClientSessionState.UseBy` accessor
so Surf can check ticket expiry through its existing public serialization bridge.

Surf keeps at most 256 origin cursors per transport. Each cursor identifies
an opaque key in the application's TLS cache and the exact ticket by digest;
it stores no independent PSK. Origins include the original hostname and port,
before alternative-service routing. A lookup must find that same ticket, valid
for the current time and certificate lifetime, with a version allowed by the
current configuration. Missing, expired, replaced, unmarked or evicted tickets
retain the configured first version. Disabling tickets also disables selection.

The underlying cache remains authoritative. For a single-use cache, the selection
lookup hands the chosen session to TLS once, without consuming it twice.
Caller configuration is cloned before version ordering changes. Cache callbacks
run without Surf's history lock. `CloseIdleConnections` retains this state;
`Close` releases it and prevents late cache writes from rebuilding it.
There is no added disk persistence or shared global browsing history.

## Packet verification

An independent peer used official aioquic 1.3.0, supporting v2/v1. Its private
test CA was explicitly trusted by the clients; certificate verification stayed
enabled. Each Surf client made three new connections with a shared TLS cache,
`ResumeVersion(true)` and explicit early data. The two client modes were standard
Go TLS and the Firefox template. The standard-TLS test configuration advertised
v2 before v1 in authenticated version information to exercise the switch.

Both sequences produced the following results:

| Connection | First Initial | Negotiated version | TLS resumed | Early data accepted |
| --- | --- | --- | --- | --- |
| Cold | v1 | v2 | false | false |
| First repeat | v2 | v2 | true | true |
| Second repeat | v2 | v2 | true | true |

The raw capture contains 71/71 packets with zero kernel drops. Wireshark decoded
the Initial versions. Official aioquic's packet-protection implementation also
authenticated all eight client 0-RTT packets using the original logged early
secrets, v2 key labels and AES-256-GCM. Each of the four resumed connections had
a decrypted request STREAM. Two Firefox packets changed destination CID and
were not associated with a connection by Wireshark; their independent AEAD
verification includes those packets rather than silently omitting them.
A second capture with a 20 ms UDP egress delay repeated all six successful
connections, with 75/75 packets and zero kernel drops.

The version-restoration rule is source-confirmed for Firefox. These new switch
captures verify Surf interoperability; they are not a capture of a native
Firefox v1-to-v2 resumption sequence or a claim of complete packet-timing parity.
Sanitized metrics, source pins and original capture hashes are in
`observations.json`. No usable tickets, TLS secrets, private certificates or raw
captures are stored here.

## Regression checks

Tests obtain real v2 tickets and check selection from a v1-first configuration,
immutability, origin/port isolation, ticket replacement and eviction, expiry,
certificate lifetime, disabled versions, disabled tickets, single-use caches,
bounded concurrent updates and shutdown. Public builder tests cover the Firefox
and standard-TLS paths, cache lifecycle and actual resumed exchanges. The QUIC
fork also verifies that compatible switching stores the negotiated version and
that legacy metadata still restores its remembered transport parameters.

The [early-data racing example](../../../../examples/http/http3_early_racing/http3_early_racing.go)
shows this setting together with the browser-specific TCP backup policy.
