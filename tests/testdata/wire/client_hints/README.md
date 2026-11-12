# Chromium 158 Client Hints reference

`chromium-158.json` contains request header fields recorded by an independent
HTTP/1.1 peer from ordinary visible Chromium **158.0.8127.0**, macOS arm64,
snapshot 1727489. Each case used a fresh browser profile and normal navigation,
JavaScript fetch POST/GET, and a subsequent warm navigation. The command line
contained only a fresh data directory, DevTools observation, and first-run
suppression. No TLS, Client Hints, User-Agent, protocol, or certificate overrides
were applied. HTTP loopback is a trustworthy origin under Chromium's normal
policy. The ephemeral authority and origin are replaced with placeholders;
actual browser brand lists, versions, OS metadata and casing remain intact.

Cases request all eight high-entropy UA hints, architecture only, a version
subset, or an empty Accept-CH. A valid Critical-CH restarts the cold navigation
before it reaches the renderer. The restarted request moves the hint block after
Accept; a warm navigation returns it before Upgrade-Insecure-Requests. Renderer
fetch requests use Blink's header-map iteration, including rehashing as the
number of enabled hints changes. A single fixed list for every opt-in subset is
insufficient.

The regression suite compares the independent UA metadata block order, its
placement relative to Accept/User-Agent/Content-Type, and casing to Surf's actual
HTTP/1 request bytes, decoded HTTP/2 HPACK fields, and decoded HTTP/3 QPACK fields.
HTTP/2 and HTTP/3 are local Surf protocol tests; the native reference in this
folder is HTTP/1.1. It does not establish native multiplexed-stream scheduling,
packet timing, Windows/Android hardware values, or complete DOM/Permissions-Policy
behavior. Chromium's unbranded two-product metadata differs intentionally from
Surf's selected Windows Google Chrome identity. The native fixture is never
rewritten to erase that difference.

A second run captured real Ethernet/TCP traffic with tcpdump in a local Docker
peer, reached by Chromium and Surf through host loopback forwarding. The
[packet comparison](packet-comparison.json) records capture hashes and scope:
all **19** requests across the four cases matched in method, path, ordered header
names/casing/values and body. Critical restarts reused the HTTP/1 connection in
both clients. Surf used explicit Mac arm64/unbranded Chromium metadata overrides
to compare the same identity; the default Windows Chrome identity was preserved.
The capture contained 267 native packets (including browser background requests)
and 123 Surf packets, with zero kernel drops in the Surf capture. Packet counts,
scheduling and timing are not asserted equal. Native reference JSON above comes
from the earlier independent run, rather than being derived from Surf output.

Browser logic is pinned to the current release sources:

- [Navigation opt-ins and hint order](https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/client_hints.cc).
- [Critical-CH: once per origin per navigation, including before redirects](https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/critical_client_hints_throttle.cc).
- [Structured Field parsing](https://github.com/chromium/chromium/blob/158.0.8127.18/services/network/public/cpp/client_hints.cc).
- [Renderer insertion](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/frame_fetch_context.cc).
- [Renderer map](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/network/http_header_map.h), [case-folded hashing](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/wtf/text/case_folding_hash.h), [bucket iteration and growth](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/wtf/hash_table.h).
- [Bounded abandoned HTTP/1 response draining](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_response_body_drainer.h).

Surf retains opt-ins in a client-local bounded origin cache. HTTP response headers
on document navigations update it; ordinary fetch/subresource responses do not.
Missing or malformed Accept-CH leaves it intact; an empty valid list clears it.
Cookies from an abandoned critical response are applied before replay. A streamed
body without GetBody is never fabricated or replayed. Explicit request hint values
and explicit ordering retain ownership. Firefox and iOS profiles do not enable
Chromium negotiation. DOM meta directives, frame policy delegation, HTTP cache
and disk persistence, and ALPS ACCEPT_CH frames are separate scopes.
