import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { peerAckObservations } from "./peer-ack-observations.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(args.in && args.out, "use --in=ROOT[,ROOT...] --out=REPORT.json");
const read = (file) => JSON.parse(readFileSync(file, "utf8"));
const lines = (file) =>
  readFileSync(file, "utf8").trim().split("\n").map(JSON.parse);
const hash = (file) =>
  createHash("sha256").update(readFileSync(file)).digest("hex");
const cases = [];
for (const root of args.in.split(","))
  for (const name of readdirSync(root).sort()) {
    if (!/^(chrome|firefox)-h3-\d+$/.test(name)) continue;
    const dir = join(root, name),
      server = read(join(dir, "server.json"));
    const requests = lines(join(dir, "requests.jsonl"));
    const trace = lines(join(dir, "transport.jsonl"));
    const labels = new Map(requests.map((r) => [r.connection, r.label]));
    const result = spawnSync(
      "tshark",
      [
        "-2",
        "-r",
        join(dir, "wire.pcap"),
        "-o",
        "tls.keylog_file:" + join(dir, "tls.keys"),
        "--no-duplicate-keys",
        "-Y",
        `udp.dstport==${server.port} && (quic.long.packet_type==0 || quic.af.sequence_number)`,
        "-T",
        "json",
      ],
      { encoding: "utf8", maxBuffer: 32 << 20 },
    );
    assert(
      !result.error && result.status === 0,
      result.error?.message || result.stderr,
    );
    const wire = peerAckObservations(JSON.parse(result.stdout), labels);
    const groups = [];
    for (const label of ["browser", "surf-preset", "surf-exact-input"]) {
      assert.equal(
        requests.filter((r) => r.label === label).length,
        11,
        "incomplete request sequence",
      );
      const connections = [];
      for (const [connection, owner] of labels) {
        if (owner !== label) continue;
        const decoded = wire
          .filter((f) => f.connection === connection)
          .map(({ connection, label, ...f }) => f);
        const received = trace
          .filter(
            (r) => r.connection === connection && r.direction === "received",
          )
          .flatMap((r) => r.ack_frequency || []);
        const unmatched = [...decoded];
        for (const frame of received) {
          const index = unmatched.findIndex((candidate) =>
            Object.entries(frame).every(
              ([key, value]) => candidate[key] === value,
            ),
          );
          assert(
            index >= 0,
            "qlog frame missing from independent Wireshark decode",
          );
          unmatched.splice(index, 1);
        }
        connections.push({
          wire_requests: decoded,
          received_requests: received,
          wire_requests_not_received: unmatched,
        });
      }
      groups.push({ label, completed_requests: 11, connections });
    }
    const network = read(join(dir, "network-summary.json"));
    assert.equal(network.error, "");
    const totals = {};
    for (const [flow, counters] of Object.entries(network.flows)) {
      const total = (totals[flow.split("|")[0]] ||= {});
      for (const [key, value] of Object.entries(counters))
        total[key] = (total[key] || 0) + value;
      assert.equal(counters.Overflow, 0);
    }
    const browser = read(join(dir, "browser.json"));
    cases.push({
      case: name,
      captured_at: browser.captured_at,
      browser:
        browser.metadata.capabilities?.browserVersion ||
        browser.metadata.product,
      host: "macOS",
      user_agent_override: browser.prefs["general.useragent.override"] || null,
      peer_legacy_min_ack_delay_us:
        server.legacy_ack_frequency_min_us ?? Number(args["peer-min-us"]),
      network: server.network,
      network_totals: totals,
      pcap_sha256: hash(join(dir, "wire.pcap")),
      trace_sha256: hash(join(dir, "transport.jsonl")),
      groups,
    });
    assert(
      Number.isFinite(cases.at(-1).peer_legacy_min_ack_delay_us),
      "missing server legacy minimum metadata",
    );
  }
assert(cases.length, "no capture cases");
writeFileSync(
  args.out,
  JSON.stringify(
    {
      schema: 1,
      method:
        "Exact encrypted UDP payloads at the server capture socket, synthetic IP/UDP envelopes. Independent Wireshark decoding is checked against every received qlog ACK_FREQUENCY frame. Original client DCIDs bind connections; sequence numbers are connection-local. Wire requests can be dropped by the path emulator before receipt. No NIC pacing or full congestion-controller parity claim.",
      cases,
    },
    null,
    2,
  ) + "\n",
);
console.log(`Verified ${cases.length} captures`);
