import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { ackObservations } from "./ack-observations.mjs";
import { ackRanges, windowUpdates } from "./bulk-packets.mjs";

function statistics(values) {
  const sorted = values.toSorted((a, b) => a - b),
    histogram = {};
  for (const value of values) histogram[value] = (histogram[value] ?? 0) + 1;
  return {
    count: sorted.length,
    median: sorted.length ? sorted[Math.floor(sorted.length / 2)] : null,
    min: sorted[0] ?? null,
    max: sorted.at(-1) ?? null,
    histogram,
  };
}

// This measures observations at the capture point, not a congestion controller's
// internal pacing decisions. ACK counts include only observed eliciting packets.
export function bulkSummary(input, index) {
  const wanted = new Set(index.connections);
  assert(wanted.size > 0, "no decoded request connections");
  const rows = input.filter((row) => wanted.has(row.conn));
  const converted = [],
    connections = {};
  const makeSide = () => ({
    packets: 0,
    unknown: 0,
    bytes: 0,
    types: {},
    max_data: [],
    max_stream_data: {},
    ping_without_stream: 0,
    ping_with_ack: 0,
    spacing: [],
    observed: new Set(),
    duplicate_packet_numbers: 0,
    out_of_order_numbers: 0,
    largest: -1,
    previous: null,
  });
  for (const row of rows) {
    const connection = (connections[row.conn] ??= {
      client_parameters: {},
      server_parameters: {},
      client: makeSide(),
      server: makeSide(),
    });
    Object.assign(connection[row.side + "_parameters"], row.parameters);
    if (row.type !== "1rtt") continue;
    const side = connection[row.side];
    side.packets++;
    side.bytes += row.bytes;
    if (side.previous !== null) {
      const spacing = (row.time - side.previous) * 1e6;
      assert(
        spacing >= -1,
        "capture timestamps are not monotonic within a direction",
      );
      side.spacing.push(Math.max(0, Math.round(spacing)));
    }
    side.previous = row.time;
    if (row.pn === null) {
      side.unknown++;
      continue;
    }
    if (side.observed.has(row.pn)) side.duplicate_packet_numbers++;
    else if (row.pn < side.largest) side.out_of_order_numbers++;
    side.observed.add(row.pn);
    side.largest = Math.max(side.largest, row.pn);
    for (const frame of row.frames) {
      side.types[frame.type] = (side.types[frame.type] ?? 0) + 1;
      if (frame.type === 16) side.max_data.push(frame.limit);
      if (frame.type === 17)
        (side.max_stream_data[frame.stream] ??= []).push(frame.limit);
    }
    if (row.frames.some((frame) => frame.type === 1)) {
      if (!row.frames.some((frame) => frame.type >= 8 && frame.type <= 15))
        side.ping_without_stream++;
      if (row.frames.some((frame) => frame.type === 2 || frame.type === 3))
        side.ping_with_ack++;
    }
    // RFC 9000: ACK, PADDING and CONNECTION_CLOSE do not elicit ACKs.
    const eliciting = row.frames.some(
      (frame) => ![0, 2, 3, 28, 29].includes(frame.type),
    );
    const ranges = row.frames
      .filter((frame) => frame.type === 2 || frame.type === 3)
      .flatMap(ackRanges);
    converted.push({
      connection: row.conn,
      packet_number: row.pn,
      direction: row.side === "server" ? "sent" : "received",
      eliciting,
      ack_ranges: ranges,
      ack_delay_ns:
        (row.frames.find((frame) => frame.type === 2 || frame.type === 3)
          ?.delay ?? 0) *
        2 ** (connection[row.side + "_parameters"].ack_delay_exponent ?? 3) *
        1000,
    });
  }
  const observations = ackObservations(converted);
  for (const connection of Object.values(connections))
    for (const name of ["client", "server"]) {
      const side = connection[name],
        params = connection[name + "_parameters"];
      const updates = (values, initial) => {
        const result = windowUpdates(values, initial);
        return { ...result, increases: statistics(result.increases) };
      };
      side.max_data = updates(side.max_data, params.initial_max_data);
      for (const [id, values] of Object.entries(side.max_stream_data)) {
        const local = Number(id) % 4 === (name === "client" ? 0 : 1),
          uni = (Number(id) & 2) !== 0;
        side.max_stream_data[id] = updates(
          values,
          uni
            ? params.initial_max_stream_data_uni
            : local
              ? params.initial_max_stream_data_bidi_local
              : params.initial_max_stream_data_bidi_remote,
        );
      }
      side.observed_spacing_us = statistics(side.spacing);
      delete side.spacing;
      delete side.previous;
      delete side.largest;
      delete side.observed;
    }
  return {
    unattributed_packets: index.unattributed ?? [],
    connections,
    ack: {
      server_eliciting: observations.server_ack_eliciting_packets,
      early: statistics(observations.early),
      late: statistics(observations.late),
      delay_ms: statistics(observations.delays),
    },
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const [prefix, requestIndex = prefix + "-requests.json"] =
    process.argv.slice(2);
  assert(prefix, "usage: bulk-summary.mjs output-prefix [request-index.json]");
  const rows = readFileSync(prefix + "-packets.jsonl", "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse);
  const index = JSON.parse(readFileSync(requestIndex));
  index.unattributed =
    JSON.parse(readFileSync(prefix + "-requests.json")).unattributed ?? [];
  const result = bulkSummary(rows, index);
  writeFileSync(
    prefix + "-summary.json",
    JSON.stringify(result, null, 2) + "\n",
    { mode: 0o600, flag: "wx" },
  );
  console.log(
    JSON.stringify({
      connections: Object.keys(result.connections),
      early_ack_median: result.ack.early.median,
      late_ack_median: result.ack.late.median,
    }),
  );
}
