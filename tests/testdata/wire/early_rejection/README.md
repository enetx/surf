# Rejected Firefox early data on the same QUIC connection

Firefox 160's HTTP/3 implementation resets its protocol state and restarts the
transactions after TLS rejects 0-RTT. It does not need another QUIC connection:

- [Neqo HTTP/3 reset](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-http3/src/connection.rs)
  recreates control streams and QPACK and clears previous stream state.
- [Neqo client events](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-http3/src/connection_client.rs)
  handles `ZeroRttRejected` separately from a failed transport connection.
- [Firefox transaction restart](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Session.cpp)
  handles the rejection event and `Finish0Rtt(true)` restores pending transactions.

Surf's Firefox desktop profile selects the generic HTTP/3 mechanism through
`HTTP3Settings().EarlyDataRestart(true).Set()`. Enabling it does not enable early
data or make unsafe request bodies eligible. The QUIC engine resets stream maps
only after the verified handshake; HTTP/3 retires its old workers before those
maps are replaced and builds fresh control/QPACK state on that connection.
Old callbacks cannot delete or activate new streams with reused IDs. A previously
closed early stream cannot emit a late RESET_STREAM for the replacement stream.
Manual low-level HTTP/3 connections retain application-controlled rejection
handling, and the generic transport default retains upstream behavior.

## Verification

`tests/http3_early_restart_test.go` exercises real encrypted UDP with trusted
local certificates and the Firefox profile. The resumed handshake is held until
the actual early request has been sent. It covers rejection with PSK resumption,
an unknown ticket, HRR, QPACK capacity reduced to zero, concurrent GET/HEAD/POST,
cancellation, an explicit opt-out, handshake failure and a verification callback
failure after the early attempt. Warm-up plus the resumed connection must be
exactly two connections; the follow-up request uses the same resumed connection.
Unsafe POST bodies arrive only after the verified handshake.

Engine regressions additionally cover late FIN cancellation, delayed completion
callbacks across stream ID reuse, draining in-flight callbacks, retiring blocked
Extended CONNECT requests and one-shot protocol-state replacement. The full
ticket/SETTINGS matrix remains independently exercised.

`surf.json` is an independent Wireshark 4.6.9 decode of the four local rejection
cases. It retains only packet numbers, stream IDs/ranges and handshake extension
IDs. It verifies new 1-RTT streams 0/2/6/10 starting at offset zero and the next
request on stream 4 on the same QUIC connection. Server EncryptedExtensions do
not accept early data. The capture has zero kernel drops; original PCAP hash is
retained. Wireshark does not decode the HRR early request and cannot associate
one late old-key HRR datagram; the test's sent-packet barrier establishes that
attempt separately. That portion is not claimed as independently decrypted.

Native Firefox was also captured against public servers with normal certificate
checks. It resumed successfully, but these attempts did not establish the exact
server rejection scenario. They are not substituted for a native rejection
golden. The implementation follows the pinned rejection sources, with controlled
Surf wire tests; complete native rejection/timing parity remains unverified.
Private TLS keys, tickets, browser profiles and raw PCAPs are not committed.
