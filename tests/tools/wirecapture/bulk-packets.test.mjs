import assert from "node:assert/strict";
import test from "node:test";
import {
  ackRanges,
  bulkPackets,
  safeInteger,
  windowUpdates,
} from "./bulk-packets.mjs";
import { bulkSummary } from "./bulk-summary.mjs";

const sample = () => ({
  _source: {
    layers: {
      frame: {
        "frame.cap_len": "100",
        "frame.len": "100",
        "frame.number": "1",
        "frame.time_epoch": "1.25",
      },
      udp: { "udp.dstport": "443", "udp.srcport": "50000" },
      quic: {
        "quic.connection.number": "2",
        "quic.packet_length": "58",
        "quic.short": {
          "quic.header_form": "0",
          "quic.packet_number": "7",
          "quic.packet_number_length": "0",
        },
        "quic.frame": [{ "quic.frame_type": "0x1" }],
      },
    },
  },
});

test("capture reduction requires complete frames and unambiguous connections", () => {
  const source = sample();
  assert.equal(bulkPackets(source, "example.com").packets[0].pn, 7);
  source._source.layers.frame["frame.cap_len"] = "99";
  assert.throws(() => bulkPackets(source, "example.com"), /truncated/);
  source._source.layers.frame["frame.cap_len"] = "100";
  delete source._source.layers.quic["quic.connection.number"];
  assert.throws(() => bulkPackets(source, "example.com"), /identity/);
  assert.throws(() => safeInteger("9007199254740993"), /unsafe/);
});

test("unknown full-width GREASE frame identifiers retain all bits", () => {
  const source = sample();
  source._source.layers.quic["quic.frame"] = [
    { "quic.frame_type": "0x3fffffffffffffff" },
  ];
  assert.equal(
    bulkPackets(source, "example.com").packets[0].frames[0].type,
    "4611686018427387903",
  );
});

test("relative capture timestamps preserve spacing when epoch is ISO 8601", () => {
  const source = sample();
  source._source.layers.frame["frame.time_epoch"] =
    "2026-11-14T08:29:37.231410000Z";
  source._source.layers.frame["frame.time_relative"] = "0.004942001";
  assert.equal(bulkPackets(source, "example.com").packets[0].time, 0.004942001);
  delete source._source.layers.frame["frame.time_relative"];
  assert.throws(() => bulkPackets(source, "example.com"), /timestamp/);
});

test("headers-only UDP placeholders cannot become packet observations", () => {
  const source = sample();
  source._source.layers.udp = { filtered: "udp" };
  assert.deepEqual(bulkPackets(source, "example.com").packets, []);
});

test("undecryptable packets without identity are explicit omissions, never guessed", () => {
  const source = sample();
  delete source._source.layers.quic["quic.connection.number"];
  delete source._source.layers.quic["quic.short"]["quic.packet_number"];
  const result = bulkPackets(source, "example.com");
  assert.deepEqual(result.packets, []);
  assert.deepEqual(result.unattributed, [
    { frame: 1, type: "1rtt", bytes: 58 },
  ]);
});

test("ACK ranges are inclusive and window probes do not grant credit", () => {
  assert.deepEqual(
    ackRanges({ largest: 20, first: 2, gaps: [0, 1], ranges: [1, 0] }),
    [
      [18, 20],
      [15, 16],
      [12, 12],
    ],
  );
  assert.throws(
    () => ackRanges({ largest: 1, first: 2, gaps: [], ranges: [] }),
    /invalid/,
  );
  assert.throws(
    () => ackRanges({ largest: 1, first: 0, gaps: [1], ranges: [0] }),
    /invalid/,
  );
  assert.deepEqual(windowUpdates([100, 150, 100, 150, 200], 100), {
    initial: 100,
    absolute: [100, 150, 100, 150, 200],
    increases: [50, 50],
    non_increasing: 3,
  });
});

test("bulk observations exclude ACK/padding, isolate connections and report undecoded packets", () => {
  const row = (conn, side, pn, time, frames) => ({
    conn,
    side,
    pn,
    time,
    frames,
    type: "1rtt",
    bytes: 50,
    parameters: {},
  });
  const ack = { type: 2, largest: 3, first: 3, gaps: [], ranges: [], delay: 1 };
  const rows = [
    row("a", "server", 0, 1, [{ type: 0 }]),
    row("a", "server", 1, 2, [
      { type: 2, largest: 0, first: 0, gaps: [], ranges: [], delay: 0 },
    ]),
    row("a", "server", 2, 3, [{ type: 14 }]),
    row("a", "server", 3, 4, [{ type: 14 }]),
    row("other", "server", 3, 4, [{ type: 14 }]),
    row("a", "client", 0, 5, [ack]),
    row("a", "client", 1, 6, [ack]),
    row("a", "server", null, 7, []),
  ];
  const result = bulkSummary(rows, { connections: ["a"] });
  assert.deepEqual(Object.keys(result.connections), ["a"]);
  assert.equal(result.ack.server_eliciting, 2);
  assert.equal(result.ack.early.count, 1);
  assert.equal(result.ack.early.median, 2);
  assert.equal(result.connections.a.server.unknown, 1);
  assert.equal(result.ack.delay_ms.median, 0.008);
  assert.throws(() => bulkSummary(rows, { connections: [] }), /no decoded/);
});
