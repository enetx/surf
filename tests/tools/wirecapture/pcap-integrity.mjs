import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

// Validate raw classic pcap records independently of Wireshark's successful
// dissection. A decoded prefix is not proof that the capture file is complete.
export function pcapIntegrity(data) {
  assert(data.length >= 24, "truncated pcap header");
  const magic = data.subarray(0, 4).toString("hex");
  const little = ["d4c3b2a1", "4d3cb2a1"].includes(magic);
  const nano = ["a1b23c4d", "4d3cb2a1"].includes(magic);
  assert(
    little || ["a1b2c3d4", "a1b23c4d"].includes(magic),
    "unsupported pcap format",
  );
  const u32 = (offset) =>
    little ? data.readUInt32LE(offset) : data.readUInt32BE(offset);
  const snaplen = u32(16),
    linktype = u32(20);
  let records = 0;
  for (let offset = 24; offset < data.length; records++) {
    assert(offset + 16 <= data.length, "truncated pcap record header");
    const captured = u32(offset + 8),
      original = u32(offset + 12);
    assert.equal(captured, original, "snap-truncated pcap record");
    assert(captured <= snaplen, "record exceeds pcap snaplen");
    assert(u32(offset + 4) < (nano ? 1e9 : 1e6), "invalid pcap timestamp");
    offset += 16 + captured;
    assert(offset <= data.length, "truncated pcap record payload");
  }
  return {
    records,
    bytes: data.length,
    linktype,
    sha256: createHash("sha256").update(data).digest("hex"),
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  assert(
    process.argv.length > 2,
    "usage: pcap-integrity.mjs capture.pcap [...]",
  );
  for (const path of process.argv.slice(2))
    console.log(JSON.stringify({ path, ...pcapIntegrity(readFileSync(path)) }));
}
