import assert from "node:assert/strict";

// A later client's TCP handshake must never be attributed to an earlier
// HTTP/3-only browser phase. Capture timestamps are server socket observations.
export function connectionTiming(initials, hellos, phase) {
  if (!phase) return null;
  assert(
    Number.isFinite(phase.start) &&
      Number.isFinite(phase.end) &&
      phase.start <= phase.end,
    "invalid capture phase",
  );
  const within = (values) =>
    values.filter(
      (t) => Number.isFinite(t) && t >= phase.start && t <= phase.end,
    );
  const udp = within(initials),
    tcp = within(hellos);
  return {
    initial_datagrams: udp.length,
    tcp_clienthellos: tcp.length,
    tcp_clienthello_after_udp_initial_ms:
      udp.length && tcp.length ? Math.round((tcp[0] - udp[0]) * 1000) : null,
  };
}
