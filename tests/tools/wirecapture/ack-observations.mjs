// Packet numbers and duplicate ACK state are local to each QUIC connection.
export function ackObservations(rows) {
  const connections = new Map();
  const early = [],
    late = [],
    delays = [];
  for (const row of rows) {
    let state = connections.get(row.connection);
    if (!state) {
      state = { sent: new Set(), seen: new Set(), first: Infinity };
      connections.set(row.connection, state);
    }
    if (row.direction === "sent") {
      state.first = Math.min(state.first, row.packet_number);
      if (row.eliciting) state.sent.add(row.packet_number);
    } else if (row.ack_ranges?.length) {
      // Bound work to observed packets; never expand an arbitrary ACK range.
      const acked = [...state.sent].filter((pn) =>
        row.ack_ranges.some(([lo, hi]) => lo <= pn && pn <= hi),
      );
      const newly = acked.filter((pn) => !state.seen.has(pn));
      for (const pn of acked) state.seen.add(pn);
      if (newly.length) {
        (Math.max(...acked) - state.first < 100 ? early : late).push(
          newly.length,
        );
        delays.push(row.ack_delay_ns / 1e6);
      }
    }
  }
  return {
    connections: connections.size,
    server_ack_eliciting_packets: [...connections.values()].reduce(
      (n, s) => n + s.sent.size,
      0,
    ),
    early,
    late,
    delays,
  };
}
