# Browser request header references

These fixtures preserve complete HTTP/1 request field sections from ordinary
visible browsers on macOS arm64. Independent loopback and LAN peers recorded the actual
method, path, ordered names/casing/values and body. Fresh profiles used only
CDP/BiDi observation, first-run/UI controls and normal navigation, fetch and form
submission. No User-Agent, TLS, certificate, DNS, proxy, protocol or fingerprint
overrides were applied. HTTP loopback follows the browsers' normal trustworthy
origin policy.

| Fixture | Native browser | Recorded scenarios |
| --- | --- | --- |
| [chrome.json](chrome.json) | Chromium 158.0.8127.0 | GET navigation; GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS fetch; clicked URL-encoded and multipart POST forms; absent bodies versus explicit empty-string uploads |
| [chrome-redirect.json](chrome-redirect.json) | Chromium 158.0.8127.0 | Fetch and form POST redirects to GET, including the resulting field placement and dropped upload fields |
| [chrome-metrics.json](chrome-metrics.json) | Chromium 158.0.8127.0 | Eight GET/POST fetches after viewport, memory, mixed and broad Client Hints opt-ins; actual metric values and full field sections |
| [firefox.json](firefox.json) | Firefox 160.0 | GET navigation; all seven fetch methods with body/no-body variants; URL-encoded, multipart and plain-text forms; programmatic submission versus actual UI clicks |
| [chrome-insecure.json](chrome-insecure.json) | Chromium 158.0.8127.0 | Ordinary non-loopback LAN HTTP: navigation and fetch without Client Hints/Fetch Metadata, even after Accept-CH/Critical-CH |
| [firefox-insecure.json](firefox-insecure.json) | Firefox 160.0 | 21 LAN HTTP navigation/fetch/form requests without Fetch Metadata, with gzip/deflate encoding advertisement |

The native Chromium fixture keeps its real unbranded Client Hints. Surf's selected
Google Chrome identity remains separate. Tests supply that explicit native brand
value when comparing the same identity; native fixtures are never rewritten to
match profile branding.

## Capture provenance

Raw capture sessions and helper scripts were retained during this audit in
`/tmp/surf-header-refactor/native-chrome` and
`/tmp/surf-header-refactor/native-firefox`. Browser metadata records the actual
binary/version, isolated profile, arguments and observation controls. These local
paths are audit artifacts, not test dependencies; the JSON fixtures in this
folder are the portable references.

The Chromium audit used a normal visible 158.0.8127.0 snapshot. Sequential fetches
and real mouse-driven form submissions produced the methods reference; a separate
ordinary session recorded redirects. The corresponding raw requests, browser
metadata and source downloads remain in the Chromium audit directory.

The separate `native-chrome/trustworthiness` and `native-firefox/lan` sessions
used the host's ordinary RFC1918 LAN address. Both reported a nonsecure context;
the peer retained full request bytes. The Chrome response offered Accept-CH and
Critical-CH, which the browser ignored on LAN HTTP. A fresh loopback control
against the same peer did negotiate and restart. No successful separate warm LAN
navigation is claimed. Both browsers advertised `gzip, deflate` and omitted
generated Client Hints/Fetch Metadata in these LAN references.

The Firefox audit used `/Applications/Firefox.app`, Firefox 160.0 build
20261104181552. Four fresh sessions retained identical complete fields and bodies
for the initial 21 requests after normalizing only ephemeral authority and the
random multipart boundary for the cross-run comparison. The final session also
recorded UI activation and captured real Ethernet/TCP traffic inside a Docker peer
forwarded to host loopback: 71 packets captured/received, zero kernel drops.
`docker-activation/requests.jsonl`, `browser.json`, `native.pcap` and the audit's
`audit.json` retain the original bytes, metadata, hashes and limits.

Committed fixtures replace ephemeral authority/origin with `<AUTHORITY>` and
`<ORIGIN>`. Header names, casing, real identity values and original multipart
boundaries remain intact. Bodies use `body_base64`. Cross-run normalization of
random boundaries does not alter the committed native references.

## How Surf uses the references

Header values and order are declared in
[Chrome's central preset](../../../../profiles/chrome/common/headers.go) and
[Firefox's central preset](../../../../profiles/firefox/common/headers.go).
Platform `compatibility.go` files delegate to those declarations.
[`HeaderContext`](../../../../profiles/header_context.go) supplies the actual
method, target OS, request kind, protocol, body metadata, redirect and Critical-CH state.
Request.Fetch()/Navigation() select the operation independently of emitted fields;
the request kind survives redirects, including across trustworthy/insecure origins.
Factories return fresh `g.MapOrd` values without mutating the request or reading
the body. Explicit Fetch Metadata chooses navigation/fetch independently of
method. Absent and explicit empty uploads can have different framing positions.

[Native method regressions](../../../header_profile_native_test.go) compare the
complete field section and body, rather than a selected-header projection.
Origin, Referer, Fetch Metadata and UI-triggered Priority are supplied as document
facts; the tests do not copy ordinary UA, Accept, cache, connection, encoding or
ordinary Priority defaults from the oracle to hide a mismatch.
[Ownership regressions](../../../header_profile_ownership_test.go) separately
verify explicit `SetHeaders`/`AddHeaders(g.MapOrd)`, values, casing, pseudo order,
redirects and retry ownership. An explicit order is not re-sorted by a profile.

HTTP/1 assertions use the recorded native casing and order. HTTP/2 and HTTP/3
assertions are local Surf wire regressions that decode HPACK/QPACK and apply
specified protocol deltas: lowercase names, pseudo-header order and omission of
Host/Connection; Chrome multiplexed Priority; Firefox HTTP/2 TE; Firefox HTTP/3
Alt-Used. These expectations are not native H2/H3 recordings of every scenario.
They do not establish equivalent packet timing, stream scheduling, congestion
behavior or HTTP/3 packet layouts.

The separate [Client Hints references](../client_hints/README.md) cover cold/warm
navigation, Critical-CH restart and subset-dependent renderer ordering. Keep those
independent fixtures and their scope when updating this methods matrix.

The additional metrics reference was captured in
`/tmp/surf-header-refactor/native-chrome/metrics` before changing the renderer
vocabulary. Each fresh ordinary Chromium profile learned one Accept-CH subset,
then sent GET and POST fetches. The source model inserts Content-Type before
hints and User-Agent afterward. The viewport, mixed and broad POST cases differ
from the previous insertion model; all eight complete field sections matched
after correction. Per-request `available_hints` contains only observed serialized
values. Tests configure them as available metadata, prime a real origin opt-in,
then compare Surf/Std field sections through H1/H2/H3 peers. They do not inject
the negotiated fields directly onto the tested fetch request.

The broad native subset emitted 24 of the 27 recognized hints. Resource-width
fields and enabled Save-Data were absent; their DOM/device context is not inferred.
Arbitrary application-header insertion histories remain outside this model.

## Source checks and boundaries

- Chromium navigation, form and redirect paths:
  [navigation_request.cc](https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/renderer_host/navigation_request.cc),
  [form_submission.cc](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/form_submission.cc) and
  [http_network_transaction.cc](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc).
- Chromium renderer insertion and iteration:
  [frame_fetch_context.cc](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/frame_fetch_context.cc),
  [HTTPHeaderMap](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/network/http_header_map.h) and
  [HashTable](https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/wtf/hash_table.h).
- Firefox fetch/referrer/upload construction:
  [FetchDriver.cpp](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/dom/fetch/FetchDriver.cpp) and
  [HttpBaseChannel.cpp](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/HttpBaseChannel.cpp).
- Firefox ordinary fetch urgency and common transaction setup:
  [UrgencyFromCoSFlags](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp#L947) and
  [SetPriorityHeader](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpChannel.cpp#L856).
- Firefox bodyless POST/PUT length insertion:
  [ConvertRequestHeadToString](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttp.cpp#L496).

Ordinary Firefox fetch uses `Priority: u=4`; the captured UI-triggered fetch uses
`u=0`. Programmatic form submission lacks Sec-Fetch-User, while a real submit click
sends `?1`. These are document/user-activation differences, not a rule inferred
from GET versus POST. Applications control their corresponding explicit fields.

Native desktop captures do not validate Android hardware, packet scheduling or
WebKit behavior. Chrome Android shares the Chromium declaration but still needs
native device evidence. Firefox Android/iOS remain explicitly labeled 148
placeholders. Chrome iOS retains its separate WebKit shape and source-derived 158
branding pending a fresh native device capture. Arbitrary renderer-authored custom
header histories, DOM policies, HTTP cache behavior and browser resource scheduling
are outside this reference matrix.
