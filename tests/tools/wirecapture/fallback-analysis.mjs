import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { connectionTiming } from "./connection-timing.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(
  args.in,
  "use --in=CAPTURE_ROOT_OR_CASE[,CAPTURE_ROOT_OR_CASE] [--out=SUMMARY_JSON]",
);
const readJSON = (path) => JSON.parse(readFileSync(path, "utf8"));
const readRows = (path) =>
  readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
const cases = [];
for (const input of args.in.split(",")) {
  const root = resolve(input);
  const directories = /^(chrome|firefox)-h3-\d+$/.test(basename(root))
    ? [root]
    : readdirSync(root)
        .filter((name) => /^(chrome|firefox)-h3-\d+$/.test(name))
        .sort()
        .map((name) => join(root, name));
  for (const directory of directories) {
    const server = readJSON(join(directory, "server.json"));
    const browser = readJSON(join(directory, "browser.json"));
    const comparison = readJSON(join(directory, "comparison.json"));
    const records = readRows(join(directory, "requests.jsonl"));
    function tshark(filter, fields) {
      const result = spawnSync(
        "tshark",
        [
          "-2",
          "-r",
          join(directory, "wire.pcap"),
          "-o",
          "tls.keylog_file:" + join(directory, "tls.keys"),
          "-d",
          `tcp.port==${server.port},tls`,
          "-Y",
          filter,
          "--no-duplicate-keys",
          "-T",
          "json",
          ...fields.flatMap((field) => ["-e", field]),
        ],
        { encoding: "utf8", maxBuffer: 16 << 20 },
      );
      assert(
        !result.error && result.status === 0,
        result.error?.message || result.stderr,
      );
      return JSON.parse(result.stdout).map((packet) => packet._source.layers);
    }
    const decoded = tshark("http.request", [
      "tcp.srcport",
      "http.request.method",
      "http.request.uri",
    ]);
    const expectedH1 = records
      .filter((r) => r.protocol === "h1")
      .map((r) => [r.connection.split(":").at(-1), r.method, r.path]);
    const actualH1 = decoded.flatMap((packet) =>
      packet["http.request.method"].map((method, i) => [
        packet["tcp.srcport"][0],
        method,
        packet["http.request.uri"][i],
      ]),
    );
    assert.deepEqual(
      actualH1,
      expectedH1,
      "HTTP/1 method, URI and connection attribution must match independent decoding",
    );
    const decodedH2 = tshark("http2.headers.method", [
      "tcp.srcport",
      "http2.headers.method",
      "http2.headers.path",
    ]);
    const actualH2 = decodedH2.flatMap((packet) =>
      packet["http2.headers.method"].map((method, i) => [
        packet["tcp.srcport"][0],
        method,
        packet["http2.headers.path"][i],
      ]),
    );
    const expectedH2 = records
      .filter((r) => r.protocol === "h2")
      .map((r) => [r.connection.split(":").at(-1), r.method, r.path]);
    assert.deepEqual(
      actualH2.toSorted(),
      expectedH2.toSorted(),
      "HTTP/2 methods, URIs and connection attribution must match independent decoding",
    );
    const initial = tshark(
      `udp.dstport==${server.port} && quic.long.packet_type==0`,
      ["frame.time_epoch"],
    );
    const hello = tshark(
      `tcp.dstport==${server.port} && tls.handshake.type==1`,
      ["frame.time_epoch"],
    );
    const firstUDP = initial.length
      ? Number(initial[0]["frame.time_epoch"][0])
      : null;
    const firstTCP = hello.length
      ? Number(hello[0]["frame.time_epoch"][0])
      : null;
    const phases = existsSync(join(directory, "phases.json"))
      ? readJSON(join(directory, "phases.json"))
      : [];
    function phaseTiming(label) {
      const phase = phases.find((p) => p.label === label);
      // Date.now() has millisecond precision; include its final millisecond.
      return connectionTiming(
        initial.map((r) => Number(r["frame.time_epoch"][0])),
        hello.map((r) => Number(r["frame.time_epoch"][0])),
        phase ? { ...phase, end: phase.end + 0.001 } : null,
      );
    }
    const groups = comparison.groups.map((group) => {
      const selected = records.filter((r) => r.label === group.label);
      assert.equal(selected.length, group.requests.length);
      assert.equal(
        selected.length,
        11,
        "the header scenario must complete all requests",
      );
      return {
        label: group.label,
        protocol_counts: group.protocol_counts,
        connections: new Set(selected.map((r) => r.connection)).size,
        sequence: selected.map((r) => [r.protocol, r.path]),
        timing: phaseTiming(group.label),
      };
    });
    let network = null;
    if (existsSync(join(directory, "network-summary.json"))) {
      const summary = readJSON(join(directory, "network-summary.json"));
      const totals = {};
      for (const [key, flow] of Object.entries(summary.flows)) {
        const direction = key.split("|")[0];
        const total = (totals[direction] ||= {
          seen: 0,
          dropped: 0,
          delivered: 0,
          reordered: 0,
          overflow: 0,
        });
        for (const field of Object.keys(total))
          total[field] += flow[field[0].toUpperCase() + field.slice(1)] || 0;
      }
      assert.equal(summary.error, "");
      assert(
        Object.values(totals).every((total) => total.overflow === 0),
        "capture queue overflow invalidates the experiment",
      );
      network = {
        one_way_delay_ms: summary.one_way_delay_ms,
        jitter_ms: summary.jitter_ms || 0,
        drop_every: summary.drop_every_per_flow_direction,
        drop_first: summary.drop_first_per_flow_direction,
        reorder_every: summary.reorder_every_per_flow_direction || 0,
        totals,
      };
    }
    cases.push({
      run: basename(dirname(directory)),
      case: basename(directory),
      browser_version:
        browser.metadata.product ||
        browser.metadata.capabilities.browserVersion,
      captured_at: browser.captured_at,
      complete: true,
      pcap_sha256: createHash("sha256")
        .update(readFileSync(join(directory, "wire.pcap")))
        .digest("hex"),
      network,
      independently_decoded_http1_requests: actualH1.length,
      independently_decoded_http2_requests: actualH2.length,
      connection_racing: comparison.connection_racing || false,
      firefox_force_alt_svc:
        browser.prefs?.[
          "network.http.http3.force-use-alt-svc-mapping-for-testing"
        ] ?? null,
      first_tcp_clienthello_after_first_udp_initial_ms: phases.length
        ? (phaseTiming("browser")?.tcp_clienthello_after_udp_initial_ms ?? null)
        : firstUDP !== null && firstTCP !== null
          ? Math.round((firstTCP - firstUDP) * 1000)
          : null,
      groups,
    });
  }
}
const report = {
  schema: 2,
  method:
    "Completed browser and Surf header scenarios; independent TLS/Wireshark verification of HTTP/1 and HTTP/2 requests. Per-client timing uses recorded phase bounds when available. The interval measures server socket observations, not TCP SYN timing or NIC pacing. No TLS secrets, profile paths or session IDs are included.",
  cases,
};
const output = JSON.stringify(report, null, 2) + "\n";
if (args.out) writeFileSync(args.out, output);
console.log(output);
