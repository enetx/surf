// Compare DATA boundaries and explicit priorities independently through Wireshark.
// Raw captures, TLS keys and temporary profiles must stay outside Git.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
const args = Object.fromEntries(
  process.argv.slice(2).map((v) => v.replace(/^--/, "").split("=")),
);
assert(
  args.in && args.out,
  "use --in=CAPTURE_ROOT[,ROOT...] --out=REPORT.json",
);
const read = (p) => JSON.parse(readFileSync(p, "utf8"));
const lines = (p) =>
  readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
const hash = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
function* nodes(v) {
  if (Array.isArray(v)) {
    for (const x of v) yield* nodes(x);
  } else if (v && typeof v === "object") {
    yield v;
    for (const x of Object.values(v)) yield* nodes(x);
  }
}
const cases = [];
for (const root of args.in.split(","))
  for (const name of readdirSync(root).filter((n) =>
    /^(chrome|firefox)-h3-/.test(n),
  )) {
    const dir = join(root, name),
      server = read(join(dir, "server.json")),
      browser = read(join(dir, "browser.json"));
    const requests = lines(join(dir, "requests.jsonl")),
      frames = lines(join(dir, "frames.jsonl"));
    const scenario = requests.some((r) => r.method === "POST")
      ? "uploads"
      : "priorities";
    const labels = ["browser", "surf-preset", "surf-exact-input"];
    const ids = new Map();
    for (const label of labels) {
      const rows = requests.filter((r) => r.label === label);
      assert.equal(rows.length, scenario === "uploads" ? 11 : 3);
      const connections = new Set(rows.map((r) => r.connection));
      for (const id of connections) ids.set(id, label);
    }
    const groups = new Map();
    for (const packet of read(join(dir, "wireshark.json"))) {
      const layers = packet._source.layers,
        udp = layers.udp;
      if (!udp || Number(udp["udp.dstport"]) !== server.port) continue;
      const port = udp["udp.srcport"];
      let g = groups.get(port);
      if (!g) {
        g = { data: [], priorities: [], headers: 0 };
        groups.set(port, g);
      }
      for (const n of nodes(layers.quic)) {
        const id = n["quic.dcid"]?.replaceAll(":", "");
        if (ids.has(id)) {
          if (g.connection) assert.equal(g.connection, id);
          g.label = ids.get(id);
          g.connection = id;
        }
      }
      for (const n of nodes(layers.http3)) {
        const kind = n["http3.frame_type"];
        if (kind === undefined) continue;
        if (BigInt(kind) === 0n)
          g.data.push({
            stream: Number(n["http3.frame_streamid"]),
            length: Number(n["http3.frame_length"]),
          });
        if (BigInt(kind) === 1n) g.headers++;
        if (BigInt(kind) === 0xf0700n)
          g.priorities.push({
            stream: Number(n["http3.priority_update_element_id"]),
            value: n["http3.priority_update_field_value"],
          });
      }
    }
    const independent = { data_frames: 0, priority_frames: 0 };
    assert.equal(
      [...groups.values()].filter((g) => g.headers).length,
      ids.size,
      "unattributed HTTP/3 connection",
    );
    for (const [connection, label] of ids) {
      const matches = [...groups.values()].filter(
        (g) => g.connection === connection,
      );
      assert.equal(
        matches.length,
        1,
        `${name}: ambiguous connection for ${label}`,
      );
      const g = matches[0];
      assert.equal(
        g.headers,
        requests.filter((r) => r.connection === connection).length,
      );
      const data = frames
        .filter((f) => f.connection === connection && f.type === "DATA")
        .map((f) => ({ stream: f.stream_id, length: f.length }));
      const priorities = frames
        .filter(
          (f) => f.connection === connection && f.type === "PRIORITY_UPDATE",
        )
        .map((f) => ({ stream: f.request_stream_id, value: f.priority }));
      assert.deepEqual(
        g.data,
        data,
        `${name}: Wireshark/peer DATA disagree for ${label}`,
      );
      assert.deepEqual(
        g.priorities,
        priorities,
        `${name}: Wireshark/peer priorities disagree for ${label}`,
      );
      independent.data_frames += data.length;
      independent.priority_frames += priorities.length;
    }
    const row = {
      case: name,
      scenario,
      captured_at: browser.captured_at,
      browser: browser.browser,
      version:
        browser.metadata.product ||
        browser.metadata.capabilities.browserVersion,
      peer_capacity: server.capacity,
      connections: Object.fromEntries(
        labels.map((label) => [
          label,
          [...ids.values()].filter((v) => v === label).length,
        ]),
      ),
      pcap_sha256: hash(join(dir, "wire.pcap")),
      requests_sha256: hash(join(dir, "requests.jsonl")),
      frames_sha256: hash(join(dir, "frames.jsonl")),
      independent_wireshark_checks: independent,
    };
    if (scenario === "uploads") {
      row.uploads = requests
        .filter((r) => r.label === "browser" && r.method === "POST")
        .map((r) => {
          const lengths = (label) => {
            const req = requests.find(
              (q) => q.label === label && q.path === r.path,
            );
            assert(req);
            return frames
              .filter(
                (f) =>
                  f.connection === req.connection &&
                  f.stream_id === req.stream_id &&
                  f.type === "DATA",
              )
              .map((f) => f.length);
          };
          const observed = lengths("browser"),
            preset = lengths("surf-preset"),
            exact = lengths("surf-exact-input");
          assert.equal(
            observed.reduce((a, b) => a + b, 0),
            exact.reduce((a, b) => a + b, 0),
            "body lengths differ",
          );
          return {
            path: r.path,
            body_bytes: observed.reduce((a, b) => a + b, 0),
            browser: observed,
            surf_preset: preset,
            surf_exact_input: exact,
            boundaries_equal:
              JSON.stringify(observed) === JSON.stringify(exact),
          };
        });
    } else {
      row.priorities = Object.fromEntries(
        labels.map((label) => [
          label,
          frames
            .filter((f) => f.label === label && f.type === "PRIORITY_UPDATE")
            .map((f) => ({ stream: f.request_stream_id, value: f.priority })),
        ]),
      );
      row.browser_observation =
        "Changing img.fetchPriority during the response emitted no additional PRIORITY_UPDATE in this scenario. Surf exact-input replay exercises manual changes separately; it does not reproduce an observed browser loading policy.";
    }
    cases.push(row);
  }
const report = {
  schema: 1,
  scope:
    "Local HTTP/3 DATA and control-frame observations, independently checked against decrypted Wireshark frames. No claim about packet pacing, loss or congestion.",
  firefox_environment:
    "Fresh temporary headless profiles; MOZ_DISABLE_CONTENT_SANDBOX=1 for these processes only.",
  cases,
};
writeFileSync(args.out, JSON.stringify(report, null, 2) + "\n");
console.log(
  JSON.stringify({
    cases: cases.length,
    uploads: cases
      .filter((c) => c.scenario === "uploads")
      .map((c) => ({
        case: c.case,
        matching: c.uploads.filter((u) => u.boundaries_equal).length,
        total: c.uploads.length,
      })),
  }),
);
