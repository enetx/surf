import assert from "node:assert/strict";
import test from "node:test";
import {
  quicPacketHeader,
  quicDatagramPadding,
  controlStreamSummary,
} from "./transport-packet.mjs";

test("long and short packet headers use actual decoded length", () => {
  for (let encoded = 0; encoded < 4; encoded++) {
    const fields = {
      "quic.header_form": "1",
      "quic.packet_number": "256",
      "quic.packet_number_length": String(encoded),
    };
    assert.deepEqual(
      quicPacketHeader({
        ...fields,
        "quic.packet_length": "74",
        "quic.long.packet_type": "2",
      }),
      { type: 2, packet_number_bytes: encoded + 1 },
    );
    assert.deepEqual(
      quicPacketHeader({
        "quic.packet_length": "74",
        "quic.short": { ...fields, "quic.header_form": "0" },
      }),
      { type: "1rtt", packet_number_bytes: encoded + 1 },
    );
  }
});
test("external datagram padding is not an application packet", () => {
  assert.equal(
    quicPacketHeader({ "_ws.expert": { "quic.coalesced_padding_data": "" } }),
    null,
  );
});
test("protected undecoded lengths remain explicitly unknown", () => {
  assert.deepEqual(
    quicPacketHeader({
      "quic.packet_length": "74",
      "quic.short": {
        "quic.header_form": "0",
        "quic.packet_number_length": "3",
      },
    }),
    { type: "1rtt", packet_number_bytes: null },
  );
});

test("external padding distinguishes zero bytes from nonzero bytes", () => {
  assert.deepEqual(
    quicDatagramPadding(
      { "udp.length": "14", "udp.payload": "01:02:03:00:00:ff" },
      [{ "quic.packet_length": "3" }],
    ),
    { bytes: 3, zero_bytes: 2, nonzero_bytes: 1 },
  );
  assert.throws(
    () => quicDatagramPadding({ "udp.length": "14", "udp.payload": "00" }, []),
    /incomplete/,
  );
  assert.throws(
    () =>
      quicDatagramPadding({ "udp.length": "9", "udp.payload": "00" }, [
        { "quic.packet_length": "2" },
      ]),
    /exceed/,
  );
});

test("captured Chrome size differences come from GREASE varints and payload", () => {
  const browser = controlStreamSummary(
    "00041b018001000006800400000740643301c0000014f0a70fb9b0e7e5a0c000001021391b2900",
  );
  const surf = controlStreamSummary(
    "00041f018001000006800400000740643301c000001d2ebea020c0000000a5e8f554c000001b2ef07a9702d28b",
  );
  assert.equal(browser.bytes, 39);
  assert.equal(surf.bytes, 45);
  const stable = (summary) =>
    summary.settings.filter((s) => s.id < 64).map((s) => [s.id, s.value]);
  assert.deepEqual(stable(browser), stable(surf));
  assert.equal(browser.settings.at(-1).value_bytes, 4);
  assert.equal(surf.settings.at(-1).value_bytes, 8);
  assert.equal(browser.frames.at(-1).payload_bytes, 0);
  assert.equal(surf.frames.at(-1).payload_bytes, 2);
  for (const summary of [browser, surf]) {
    const grease = summary.settings.at(-1);
    assert.equal((grease.id - 33) % 31, 0);
    assert(grease.value <= 0xffffffff);
  }
});

test("control stream decoder rejects incomplete prefixes", () => {
  for (const data of ["", "01", "0004", "00040180", "00040201"]) {
    assert.throws(() => controlStreamSummary(data));
  }
});
