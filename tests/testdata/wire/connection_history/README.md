# Chrome 158 HTTP/3 support history and TCP backup delay

Reference: ordinary Google Chrome for Testing 158.0.8127.18, Linux aarch64,
revision 6449d9f9a6a906edff724b7b220199b3fde4615c. This is the official branded
testing build, not an unbranded Chromium binary or a Windows packet capture.
Surf's desktop profile continues to use the Windows Chrome identity.

## Confirmed source behavior

- [QuicSessionPool::GetTimeDelayForWaitingJob](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_pool.cc)
  gates the delay on the pool's current-network support, not success at the
  requested server alone. OnJobComplete establishes support after success.
  RTT and recently-broken state remain server-specific. Without an RTT, the
  base delay is 300ms; otherwise it is 1.5 times the RTT in integer microseconds.
- [MaybeSetWaitTimeForMainJob](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_factory_job_controller.cc)
  caps the complete delay at three seconds. A usable H2 session can suppress
  the delay under the default policy. DNS/connection initiation and failure
  callbacks determine when the browser starts or releases that timer.
- [Desktop trial configuration](https://github.com/chromium/chromium/blob/158.0.8127.18/testing/variations/fieldtrial_testing_config.json)
  selects DelayMainJobStudyDesktop/EnabledWith50ms and AdditionalDelay=50ms.
  The captured build uses this configuration without experiment flags.
  Android's separate default is 100ms in
  [net/base/features.cc](https://github.com/chromium/chromium/blob/158.0.8127.18/net/base/features.cc).
  Release Chrome's externally assigned variations can differ from this reference.

## Fresh native evidence

Two new profiles used CDP only for ordinary no-cors, credentials-omitted,
cache-no-store fetches. Passive NetLog Everything and TLS key logging were
enabled; no certificate, DNS, feature, origin-mapping or QUIC override was used.
The browser sandbox stayed enabled. Xvfb provided an ordinary visible display.

The first run made three requests each to aiortc, Google, www.cloudflare.com,
cloudflare.com and Google Storage. Four first-origin controller jobs recorded
a 350ms delayed-TCP policy after QUIC had worked in the pool. Session creation
reported require_confirmation=false at these later origins. Startup/background
Google traffic also exists in the capture: the first application fetch must not
be misrepresented as the first request in the whole browser's network context.

In the second run, chrome://version was read after the fetches. It reported
variations-source=field-trial-config and seed type Null. Decoding the page's
variation command independently confirmed AdditionalDelayMainJob associated with
DelayMainJobStudyDesktop/EnabledWith50ms and AdditionalDelay=50ms. This explains
the observed 350ms without assuming that the C++ desktop feature default is on.

tcpdump observed the container's actual eth0 packets. GRO/GSO/TSO and UDP
segmentation were disabled; there was no netem impairment. Both captures have
zero reported kernel drops and complete, untruncated classic-pcap records.
TShark 4.6.9 independently decrypted application GETs at the relevant later
origins. Opaque fetch completion by itself does not prove H3 or readable status.
The observations retain only verified decoded requests, controller delays and
sanitized provenance. Original profiles, NetLogs, captures and traffic secrets
remain private.

## Surf implementation and regression scope

The generic racer now retains confirmed success for its transport session.
QUICWorked continues to describe the current origin; the new public
ConnectionRacingInfo.QUICWorkedInClient describes shared support. This preserves
existing custom callbacks while allowing the profile to apply the source policy.

Failures and RTT never leak between origins. A failure does not erase support
established elsewhere; success elsewhere does not clear that origin's error.
Unconfirmed early readiness, failures and cancellations establish no support.
A full handshake can establish support in the background after TCP wins.
Closing idle connections and evicting an origin's bounded history retain the
session-wide observation. Independent built clients start without it.

Chrome desktop adds 50ms, Android adds 100ms, and the total is capped at three
seconds without duration overflow. Firefox keeps its 100ms backup policy.
Explicit TCPFallbackDelay and custom ConnectionRacingPolicy remain authoritative.
No new builder flags, public interfaces, forks or engine changes were needed.

Deterministic internal tests cover history, failure, cancellation, early readiness,
background completion and cleanup. Public builder tests use real TLS/QUIC peers
with trusted test certificates, three separate origins, two independent clients
and idle cleanup, for both Chrome and Firefox. A private Linux loopback tcpdump
and passive TLS keys independently verify the H3 application exchanges.

Run from Surf's module root against published dependencies:

```sh
GOTOOLCHAIN=go1.27.4 GOWORK=off go test -race ./internal/connrace ./tests \
  -run 'ConnectionRac|SourceDelayBoundaries|ClientHistory' -count=30
```

For passive diagnostics only, SURF_RACING_KEYLOG may name a private mode-0600
file. Capture loopback before running the public test above and let tcpdump drain
before SIGINT. Decrypt with `tshark -r PRIVATE.pcap -o tls.keylog_file:PRIVATE.keys`.
Never commit the original capture or keys.

## Remaining limits

Surf's support lifetime is one built client's HTTP/3 transport. It does not
subscribe to Chromium-style OS network notifications, persist the last working
local address or import browser NetworkAnonymizationKeys. Fixed SOCKS routes own
separate transports; request-selected TCP proxies bypass this direct QUIC racer.

This change does not implement Chrome's network-dependent early-data admission,
the complete DNS/Alt-Svc job scheduler, available-H2 delay suppression, pre-DNS
timer admission, proactive/default QUIC eligibility or document resource ordering.
It does not explain the earlier cold Firefox no-reply observation under netem.
The native 350ms log is a selected policy, not proof of an identical NIC delay:
transport readiness can cancel a backup, and DNS, task scheduling and the OS affect
wire timing. No full protocol-choice or packet-timing parity is claimed.
