# Cached initial RTT

Chromium 157 reads positive per-origin smoothed RTT from HttpServerProperties
before creating the next QUIC connection. It records that information when a
session goes away and 1-RTT keys are available. Both reads and writes exclude
proxy paths. The wire parameter `initial_round_trip_time_us` (`0x3127`) carries
the actual measured estimate in whole microseconds, with minimal QUIC varint
encoding. It is absent on a cold direct connection under the desktop defaults.

QUICHE separately clamps its local untrusted initial estimate to 10ms..1s.
Before any real measurement, PTO uses three initial RTTs; the cold estimate is
100ms. A real measurement replaces the seed. The wire value is not clamped to
those local recovery bounds.

Pinned primary sources:

- [Chromium 157 cached estimate and proxy exclusion](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/quic/quic_session_pool.cc#2621).
- [Recording a retiring session](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/quic/quic_session_pool.cc#2812).
- [QUICHE initial RTT application and clamping](https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_sent_packet_manager.cc#L126).
- [Bounds and cold estimate](https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_constants.h#L102).
- [Initial PTO factor](https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_sent_packet_manager.cc#L58).
- [Minimal integer parameter encoding](https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/crypto/transport_parameters.cc#L173).

Surf's Chrome profile configures the same values through the public fluent API:

```go
builder.QUICSettings().
    CachedInitialRTT(0x3127, 10*time.Millisecond, time.Second).
    InitialPTOMultiplier(3).
    Set()
```

The browser parameter ID, bounds and factor live in the profile. The QUIC fork
provides only an explicit initial RTT, a pre-measurement PTO factor and a safe
flag identifying actual RTT measurements. Its defaults retain upstream behavior.

History belongs to one Surf transport and is bounded to 256 origins. A new dial
samples the previous connection when HTTP/3 replaces it, preserving access to
statistics after idle closure and while a GOAWAY connection drains. Generation
checks prevent older attempts from overwriting newer state. Failed handshakes
do not seed history; DNS failure preserves the preceding session's measurement.
Host/port and client boundaries remain isolated, and Close releases the history.
CloseIdleConnections preserves it for reconnection. This is runtime history;
disk persistence and OS cellular/network-type detection remain separate work.

Tests compare the emitted value with the actual preceding connection's final
ConnectionStats, check cold omission, Firefox and explicit opt-out, exercise
SOCKS proxy exclusion and failed handshakes, validate bounds/parameter ownership,
and stress concurrent cache updates. Engine tests cover native defaults,
restoration, first samples, zero variance, cloning, migration and PTO scaling.

RTT itself varies with the network. Stable comparisons normalize the value and
its resulting minimal width while retaining parameter presence and rejecting a
nonminimal encoding as a different fingerprint. Raw fixtures retain the exact
captured value/width, and on-wire tests compare the complete integer.
