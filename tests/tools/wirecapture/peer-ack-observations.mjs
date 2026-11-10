import assert from "node:assert/strict";

function* nodes(value) {
  if (Array.isArray(value)) for (const item of value) yield* nodes(item);
  else if (value && typeof value === "object") {
    yield value;
    for (const item of Object.values(value)) yield* nodes(item);
  }
}

const integer = (value) => {
  const number = Number(value);
  assert(Number.isSafeInteger(number) && number >= 0, "invalid frame integer");
  return number;
};

// Bind Wireshark connection numbers to original client DCIDs, rather than UDP
// ports: a browser can open multiple QUIC connections on the same socket.
export function peerAckObservations(packets, labels) {
  const connections = new Map(),
    requests = [];
  for (const row of packets) {
    const layer = row._source.layers;
    const datagramNumber = [...nodes(layer.quic)].find(
      (n) => n["quic.connection.number"] !== undefined,
    )?.["quic.connection.number"];
    for (const packet of [layer.quic].flat().filter(Boolean)) {
      const parts = [...nodes(packet)];
      const number =
        parts.find((n) => n["quic.connection.number"] !== undefined)?.[
          "quic.connection.number"
        ] ?? datagramNumber;
      const frames = parts.filter(
        (n) => n["quic.af.sequence_number"] !== undefined,
      );
      const dcid = packet["quic.dcid"]?.replaceAll(":", "");
      if (labels.has(dcid)) {
        assert(number !== undefined, "Initial missing connection attribution");
        const previous = connections.get(number);
        assert(
          !previous || previous === dcid,
          "ambiguous connection attribution",
        );
        connections.set(number, dcid);
      }
      for (const frame of frames) {
        const flag = integer(frame["quic.af.reordering_threshold"]);
        // The legacy ignore_order byte has the same encoding as 0/1 in this
        // Wireshark field. This analyzer is only for negotiated legacy captures.
        assert(flag <= 1, "not a legacy ignore_order flag");
        requests.push({
          number,
          sequence: integer(frame["quic.af.sequence_number"]),
          tolerance: integer(frame["quic.af.ack_eliciting_threshold"]),
          max_ack_delay_us: integer(frame["quic.af.request_max_ack_delay"]),
          ignore_order: flag === 1,
        });
      }
    }
  }
  return requests.map(({ number, ...request }) => {
    const connection = connections.get(number);
    assert(connection, "ACK_FREQUENCY missing Initial attribution");
    return { connection, label: labels.get(connection), ...request };
  });
}
