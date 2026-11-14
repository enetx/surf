import assert from "node:assert/strict";
import test from "node:test";
import { pcapIntegrity } from "./pcap-integrity.mjs";

function capture(little, nano) {
  const data = Buffer.alloc(43);
  data.writeUInt32BE(
    little ? (nano ? 0x4d3cb2a1 : 0xd4c3b2a1) : nano ? 0xa1b23c4d : 0xa1b2c3d4,
  );
  const write = (value, offset) =>
    little
      ? data.writeUInt32LE(value, offset)
      : data.writeUInt32BE(value, offset);
  write(65535, 16);
  write(1, 20);
  write(1, 24);
  write(nano ? 999999999 : 999999, 28);
  write(3, 32);
  write(3, 36);
  return data;
}
test("pcap integrity supports both byte orders and timestamp precisions", () => {
  for (const little of [false, true])
    for (const nano of [false, true]) {
      const result = pcapIntegrity(capture(little, nano));
      assert.equal(result.records, 1);
      assert.equal(result.bytes, 43);
      assert.equal(result.linktype, 1);
    }
});
test("truncated pcap records, snap lengths and timestamps cannot pass", () => {
  const data = capture(true, false);
  for (let size = 0; size < data.length; size++) {
    if (size !== 24) assert.throws(() => pcapIntegrity(data.subarray(0, size)));
  }
  data.writeUInt32LE(4, 36);
  assert.throws(() => pcapIntegrity(data), /snap-truncated/);
  data.writeUInt32LE(3, 36);
  data.writeUInt32LE(2, 16);
  assert.throws(() => pcapIntegrity(data), /snaplen/);
  data.writeUInt32LE(65535, 16);
  data.writeUInt32LE(1000000, 28);
  assert.throws(() => pcapIntegrity(data), /timestamp/);
});
