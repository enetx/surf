// Inspect actual decrypted client frames; transport envelopes are synthetic.
import assert from "node:assert/strict";
import {
  quicPacketHeader,
  quicDatagramPadding,
  controlStreamSummary,
} from "./transport-packet.mjs";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

const args = Object.fromEntries(
  process.argv.slice(2).map((v) => v.replace(/^--/, "").split("=")),
);
assert(args.in && args.out, "use --in=ROOT[,ROOT...] --out=REPORT.json");
const read = (p) => JSON.parse(readFileSync(p, "utf8"));
function* nodes(v) {
  if (Array.isArray(v)) for (const x of v) yield* nodes(x);
  else if (v && typeof v === "object") {
    yield v;
    for (const x of Object.values(v)) yield* nodes(x);
  }
}
const many = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const number = (v) => Number(BigInt(v));
const cases = [];
for (const root of args.in.split(","))
  for (const name of readdirSync(root).sort()) {
    if (!/^(chrome|firefox)-h[23]-\d+$/.test(name)) continue;
    const dir = join(root, name),
      server = read(join(dir, "server.json"));
    const requests = readFileSync(join(dir, "requests.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    const labels = new Map(requests.map((r) => [r.connection, r.label]));
    for (const label of ["browser", "surf-preset", "surf-exact-input"]) {
      assert.equal(
        requests.filter((r) => r.label === label).length,
        11,
        `${name}: incomplete sequence`,
      );
    }
    const udp = server.protocol === "h3",
      layer = udp ? "udp" : "tcp";
    const result = spawnSync(
      "tshark",
      [
        "-2",
        "-r",
        join(dir, "wire.pcap"),
        "-o",
        "tls.keylog_file:" + join(dir, "tls.keys"),
        "-d",
        `tcp.port==${server.port},tls`,
        "-Y",
        `${layer}.dstport==${server.port}`,
        "--no-duplicate-keys",
        "-T",
        "json",
        "-J",
        `frame ${layer} ${udp ? "quic" : "http2"}`,
      ],
      { encoding: "utf8", maxBuffer: 128 << 20 },
    );
    assert.equal(result.status, 0, result.error?.message || result.stderr);
    const groups = new Map();
    for (const row of JSON.parse(result.stdout)) {
      const l = row._source.layers,
        port = l[layer][`${layer}.srcport`];
      if (!groups.has(port))
        groups.set(port, {
          label: labels.get("127.0.0.1:" + port),
          initials: [],
          handshake_reply: null,
          handshake_finished_reply: null,
          undecoded_packets: 0,
          first_application_packet: null,
          packet_number_lengths: {},
          ack_packets: 0,
          ack_only_pings: 0,
          other_pings: 0,
          stream_credit: [],
          connection_credit: [],
          window_updates: [],
        });
      const g = groups.get(port);
      if (udp) {
        const packets = many(l.quic),
          types = [],
          decoded = [];
        for (const q of packets) {
          // Wireshark also emits a metadata-only QUIC object for random
          // padding outside packets. It is not an encrypted 1-RTT packet.
          const header = quicPacketHeader(q);
          if (!header) continue;
          g.label ||= labels.get(q["quic.dcid"]?.replaceAll(":", ""));
          const type = header.type;
          types.push(type);
          const frames = [...nodes(q)].filter(
            (n) => n["quic.frame_type"] !== undefined,
          );
          const kinds = frames.map((n) => number(n["quic.frame_type"]));
          const pnLength = header.packet_number_bytes;
          if (pnLength === null) g.undecoded_packets++;
          if (pnLength !== null) {
            const counts = (g.packet_number_lengths[type] ||= {});
            counts[pnLength] = (counts[pnLength] || 0) + 1;
          }
          const packet = {
            type,
            packet_number_bytes: pnLength,
            encoded_bytes: number(q["quic.packet_length"]),
            acknowledgments: frames
              .filter((n) => [2, 3].includes(number(n["quic.frame_type"])))
              .map((n) => ({
                delay: number(n["quic.ack.ack_delay"]),
                largest: number(n["quic.ack.largest_acknowledged"]),
              })),
            new_connection_id_sequences: frames
              .filter((n) => number(n["quic.frame_type"]) === 24)
              .map((n) => number(n["quic.nci.sequence"])),
            frame_types: kinds,
            stream_ids: frames
              .filter(
                (n) =>
                  number(n["quic.frame_type"]) >= 8 &&
                  number(n["quic.frame_type"]) <= 15,
              )
              .map((n) => number(n["quic.stream.stream_id"])),
          };
          const control = frames.find(
            (n) =>
              number(n["quic.frame_type"]) >= 8 &&
              number(n["quic.frame_type"]) <= 15 &&
              number(n["quic.stream.stream_id"]) === 2 &&
              (n["quic.stream.offset"] === undefined ||
                number(n["quic.stream.offset"]) === 0),
          );
          if (control && control["quic.stream_data"])
            packet.control_stream = controlStreamSummary(
              control["quic.stream_data"],
            );
          decoded.push(packet);
          if (type === "1rtt" && !g.first_application_packet)
            g.first_application_packet = packet;

          if (type === 0 && kinds.includes(6)) {
            g.initials.push({
              dcid_length: number(q["quic.dcil"]),
              crypto: frames
                .filter((n) => number(n["quic.frame_type"]) === 6)
                .map((n) => ({
                  offset: number(n["quic.crypto.offset"]),
                  length: number(n["quic.crypto.length"]),
                })),
              frame_types: kinds,
            });
          }
          if (type === "1rtt") {
            if (kinds.some((k) => k === 2 || k === 3)) g.ack_packets++;
            const pings = kinds.filter((k) => k === 1).length;
            if (
              kinds.some((k) => k === 2 || k === 3) &&
              kinds.every((k) => k <= 3)
            )
              g.ack_only_pings += pings;
            else g.other_pings += pings;
            for (const n of frames) {
              if (number(n["quic.frame_type"]) === 17)
                g.stream_credit.push({
                  stream: number(n["quic.msd.stream_id"]),
                  limit: number(n["quic.msd.maximum_stream_data"]),
                });
              if (number(n["quic.frame_type"]) === 16)
                g.connection_credit.push(number(n["quic.md.maximum_data"]));
            }
          }
        }
        const reply = {
          udp_payload_bytes: number(l.udp["udp.length"]) - 8,
          datagram_padding_bytes: quicDatagramPadding(l.udp, packets).bytes,
          datagram_padding: quicDatagramPadding(l.udp, packets),
          packet_types: types,
          packets: decoded,
        };
        if (types.includes(2) && !g.handshake_reply) g.handshake_reply = reply;
        if (
          !g.handshake_finished_reply &&
          decoded.some((p) => p.type === 2 && p.frame_types.includes(6))
        )
          g.handshake_finished_reply = reply;
      } else
        for (const n of nodes(l.http2)) {
          if (n["http2.type"] !== "8") continue;
          const increment = [...nodes(n)].find(
            (v) => v["http2.window_update.window_size_increment"] !== undefined,
          );
          assert(increment);
          g.window_updates.push({
            stream: number(n["http2.streamid"]),
            increment: number(
              increment["http2.window_update.window_size_increment"],
            ),
          });
        }
    }
    for (const g of groups.values()) {
      assert(g.label, `${name}: unattributed client connection`);
      if (udp)
        assert(
          g.initials.length && g.handshake_reply,
          `${name}: incomplete Initial/Handshake decode`,
        );
    }
    cases.push({
      case: name,
      protocol: server.protocol,
      browser: read(join(dir, "browser.json")),
      pcap_sha256: createHash("sha256")
        .update(readFileSync(join(dir, "wire.pcap")))
        .digest("hex"),
      groups: [...groups.values()],
    });
  }
writeFileSync(
  args.out,
  JSON.stringify(
    {
      schema: 1,
      scope:
        "Decrypted client frame semantics and UDP payload sizes. Synthetic TCP envelopes; no NIC pacing, TCP segmentation, congestion or loss parity claim.",
      cases,
    },
    null,
    2,
  ) + "\n",
);
for (const c of cases)
  for (const g of c.groups)
    console.log(
      JSON.stringify({
        case: c.case,
        label: g.label,
        initial_crypto_frames: g.initials.map((p) => p.crypto.length),
        initial_dcid_lengths: g.initials.map((p) => p.dcid_length),
        handshake: g.handshake_reply,
        ack_only_pings: g.ack_only_pings,
        stream_credit_updates: g.stream_credit.length,
        window_updates: g.window_updates.length,
      }),
    );
