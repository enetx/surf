import assert from "node:assert/strict";
import { quicPacketHeader } from "./transport-packet.mjs";

const many = (value) =>
  value === undefined ? [] : Array.isArray(value) ? value : [value];
export function safeInteger(value) {
  const number = BigInt(value);
  assert(
    number >= 0n && number <= BigInt(Number.MAX_SAFE_INTEGER),
    "unsafe QUIC integer",
  );
  return Number(number);
}
function* nodes(value) {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const child of value) yield* nodes(child);
    return;
  }
  yield value;
  for (const child of Object.values(value)) yield* nodes(child);
}

// Only authenticated decoded packet numbers are eligible for ACK analysis.
// A tuple is not a connection identity: Wireshark's connection number is used.
export function bulkPackets(row, authority, serverPort = "443") {
  const layers = row._source.layers;
  const result = { packets: [], requests: [], unattributed: [] };
  if (!layers.quic) return result;
  assert.equal(
    layers.frame["frame.cap_len"],
    layers.frame["frame.len"],
    "truncated capture frame",
  );
  const numbers = new Set(
    [...nodes(layers.quic)]
      .map((v) => v["quic.connection.number"])
      .filter((v) => v !== undefined),
  );
  const fallback = numbers.size === 1 ? [...numbers][0] : undefined;
  // A headers-only TShark export retains {filtered:"udp"} placeholders.
  // Such rows provide request identity, never packet direction or timing.
  for (const packet of layers.udp?.["udp.dstport"] !== undefined
    ? many(layers.quic)
    : []) {
    const header = quicPacketHeader(packet);
    if (!header) continue;
    const conn = packet["quic.connection.number"] ?? fallback;
    if (
      conn === undefined &&
      numbers.size === 0 &&
      header.packet_number_bytes === null
    ) {
      // Background traffic or a lost Initial can leave Wireshark without a
      // connection and decryption state. Retain the omission explicitly;
      // neither tuples nor guessed packet numbers may fill it in.
      result.unattributed.push({
        frame: safeInteger(layers.frame["frame.number"]),
        type: header.type,
        bytes: safeInteger(packet["quic.packet_length"]),
      });
      continue;
    }
    assert(conn !== undefined, "ambiguous or missing QUIC connection identity");
    const udp = layers.udp;
    assert(
      udp["udp.dstport"] === serverPort || udp["udp.srcport"] === serverPort,
      "unexpected server port",
    );
    const short = packet["quic.short"] ?? packet;
    const record = {
      frame: safeInteger(layers.frame["frame.number"]),
      // Wireshark 4.6 may print time_epoch as ISO 8601. The numeric relative
      // field also preserves sub-millisecond spacing without date parsing.
      time: Number(
        layers.frame["frame.time_relative"] ?? layers.frame["frame.time_epoch"],
      ),
      conn,
      side: udp["udp.dstport"] === serverPort ? "client" : "server",
      type: header.type,
      pn:
        short["quic.packet_number"] === undefined
          ? null
          : safeInteger(short["quic.packet_number"]),
      pn_bytes: header.packet_number_bytes,
      bytes: safeInteger(packet["quic.packet_length"]),
      frames: [],
      parameters: {},
    };
    assert(Number.isFinite(record.time), "invalid capture timestamp");
    for (const field of nodes(packet)) {
      if (field["quic.frame_type"] !== undefined) {
        const number = BigInt(field["quic.frame_type"]);
        // Unknown GREASE types may span all 62 bits; preserve them losslessly.
        assert(number >= 0n && number < 1n << 62n, "invalid QUIC frame type");
        const type =
          number <= BigInt(Number.MAX_SAFE_INTEGER)
            ? Number(number)
            : number.toString();
        const frame = { type };
        if (type === 2 || type === 3) {
          frame.largest = safeInteger(field["quic.ack.largest_acknowledged"]);
          frame.delay = safeInteger(field["quic.ack.ack_delay"]);
          frame.first = safeInteger(field["quic.ack.first_ack_range"]);
          frame.gaps = many(field["quic.ack.gap"]).map(safeInteger);
          frame.ranges = many(field["quic.ack.ack_range"]).map(safeInteger);
          assert.equal(
            frame.gaps.length,
            safeInteger(field["quic.ack.ack_range_count"]),
          );
          assert.equal(frame.gaps.length, frame.ranges.length);
        }
        if (type === 16)
          frame.limit = safeInteger(field["quic.md.maximum_data"]);
        if (type === 17) {
          frame.stream = safeInteger(field["quic.msd.stream_id"]);
          frame.limit = safeInteger(field["quic.msd.maximum_stream_data"]);
        }
        if (type >= 8 && type <= 15) {
          frame.stream = safeInteger(field["quic.stream.stream_id"]);
          frame.offset = safeInteger(field["quic.stream.offset"] ?? 0);
          frame.fin =
            field["quic.frame_type_tree"]?.["quic.stream.fin"] === "1";
          frame.length =
            field["quic.stream.length"] === undefined
              ? (field["quic.stream_data"] ?? "").replaceAll(":", "").length / 2
              : safeInteger(field["quic.stream.length"]);
          assert(Number.isSafeInteger(frame.length), "invalid STREAM length");
        }
        record.frames.push(frame);
      }
      for (const [key, value] of Object.entries(field)) {
        if (
          /^tls\.quic\.parameter\.(initial_max_data|initial_max_stream_data_bidi_local|initial_max_stream_data_bidi_remote|initial_max_stream_data_uni|ack_delay_exponent)$/.test(
            key,
          )
        ) {
          record.parameters[key.split(".").at(-1)] = safeInteger(value);
        }
      }
    }
    result.packets.push(record);
  }
  for (const field of nodes(layers.http3)) {
    if (!field["http3.headers.header"]) continue;
    const fields = many(field["http3.headers.header"]).map((h) => [
      h["http3.header.header.name"],
      h["http3.headers.header.value"],
    ]);
    const map = Object.fromEntries(fields);
    if (map[":authority"] !== authority || !map[":path"]) continue;
    const id = new URL(map[":path"], "https://" + authority).searchParams.get(
      "case",
    );
    if (!id) continue;
    assert(fallback !== undefined, "ambiguous request connection identity");
    result.requests.push({
      id,
      connection: fallback,
      stream: safeInteger(field["http3.frame_streamid"]),
      fields,
    });
  }
  return result;
}

// RFC 9000 section 19.3: wire lengths are inclusive ranges, and gaps omit two.
export function ackRanges(frame) {
  assert.equal(frame.gaps.length, frame.ranges.length);
  let low = frame.largest - frame.first;
  assert(low >= 0, "invalid first ACK range");
  const result = [[low, frame.largest]];
  for (let i = 0; i < frame.gaps.length; i++) {
    const high = low - frame.gaps[i] - 2;
    low = high - frame.ranges[i];
    assert(low >= 0 && high >= low, "invalid ACK range");
    result.push([low, high]);
  }
  return result;
}

// Retransmitted MAX_* frames and probes that repeat credit are not increases.
export function windowUpdates(values, initial) {
  let previous = initial,
    repeats = 0;
  const increases = [];
  for (const value of values) {
    if (previous !== undefined) {
      if (value > previous) increases.push(value - previous);
      else repeats++;
    }
    previous = Math.max(previous ?? 0, value);
  }
  return { initial, absolute: values, increases, non_increasing: repeats };
}
