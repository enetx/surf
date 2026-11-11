import assert from "node:assert/strict";
import test from "node:test";
import { udpCapture } from "./netlog.mjs";

test("UDP association uses Initial DCID instead of the pool job dependency", () => {
  const types = { QUIC_SESSION: 1, UDP_BYTES_SENT: 2, UDP_BYTES_RECEIVED: 3 };
  const payload = Buffer.from([0xc0, 0, 0, 0, 1, 2, 0xab, 0xcd, 0, 0]);
  const log = {
    constants: { logEventTypes: types },
    events: [
      {
        type: 1,
        source: { id: 7 },
        params: { connection_id: "abcd", source_dependency: { id: 999 } },
      },
      {
        type: 2,
        source: { id: 8 },
        time: "1000.25",
        params: {
          bytes: payload.toString("base64"),
          byte_count: payload.length,
        },
      },
      {
        type: 3,
        source: { id: 8 },
        time: "1001.5",
        params: {
          bytes: payload.toString("base64"),
          byte_count: payload.length,
        },
      },
    ],
  };
  const result = udpCapture(log, 7);
  assert.equal(result.socket, 8);
  assert.equal(result.packets, 2);
  assert.equal(result.data.readUInt32LE(20), 101);
  assert.deepEqual(
    result.data.subarray(24 + 16 + 28, 24 + 16 + 28 + payload.length),
    payload,
  );
  const broken = structuredClone(log);
  broken.events[1].params.byte_count++;
  assert.throws(() => udpCapture(broken, 7));
  const ambiguous = structuredClone(log);
  ambiguous.events.push({ ...log.events[1], source: { id: 9 } });
  assert.throws(() => udpCapture(ambiguous, 7));
});
