import assert from "node:assert/strict";
import { ackObservations } from "./ack-observations.mjs";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(args.in, "use --in=PRIVATE_CAPTURE_DIRECTORY [--out=SUMMARY_JSON]");
const root = resolve(args.in),
  cases = [];
function stats(values) {
  const sorted = values.toSorted((a, b) => a - b),
    histogram = {};
  for (const n of values) histogram[n] = (histogram[n] || 0) + 1;
  const median = sorted.length
    ? (sorted[Math.floor((sorted.length - 1) / 2)] +
        sorted[Math.floor(sorted.length / 2)]) /
      2
    : null;
  return { ack_frames: values.length, median, histogram };
}
for (const name of readdirSync(root).sort()) {
  if (!/^(chrome|firefox)-h3-\d+$/.test(name)) continue;
  const dir = join(root, name);
  const browser = JSON.parse(readFileSync(join(dir, "browser.json"), "utf8"));
  const rows = readFileSync(join(dir, "transport.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse);
  const groups = [];
  for (const label of ["browser", "surf-preset", "surf-exact-input"]) {
    const observation = ackObservations(rows.filter((r) => r.label === label));
    const { early, late, delays } = observation;
    assert(
      observation.server_ack_eliciting_packets > 1000,
      "capture must include a bulk response beyond the transition",
    );
    groups.push({
      label,
      connections: observation.connections,
      server_ack_eliciting_packets: observation.server_ack_eliciting_packets,
      early: stats(early),
      late: stats(late),
      max_reported_ack_delay_ms: Math.max(...delays),
    });
  }
  cases.push({
    case: name,
    browser_metadata: browser.metadata,
    captured_at: browser.captured_at,
    pcap_sha256: createHash("sha256")
      .update(readFileSync(join(dir, "wire.pcap")))
      .digest("hex"),
    groups,
  });
}
const report = {
  schema: 2,
  method:
    "Server-side qlog of actual decrypted peer ACK frames; newly acknowledged server ack-eliciting packets per ACK. Early/late split at packet-number span 100. Includes batching, piggybacking and tracing overhead; no NIC timing parity claim.",
  cases,
};
const output = JSON.stringify(report, null, 2) + "\n";
if (args.out) writeFileSync(args.out, output);
console.log(output);
