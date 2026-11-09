import assert from "node:assert/strict";
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(args.in, "use --in=PRIVATE_CAPTURE_DIRECTORY [--out=SUMMARY_DIRECTORY]");
const root = resolve(args.in),
  output = resolve(args.out || root);
mkdirSync(output, { recursive: true });
const read = (p) => JSON.parse(readFileSync(p, "utf8"));
const lines = (p) => readFileSync(p, "utf8").trim().split("\n").map(JSON.parse);
const many = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const hex = (s) => (s || "").replaceAll(":", "");
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function hpackUpdates(raw) {
  const b = Buffer.from(raw, "hex"),
    updates = [];
  let pos = 0;
  while (pos < b.length && (b[pos] & 0xe0) === 0x20) {
    let n = b[pos++] & 31;
    if (n === 31) {
      let shift = 0,
        v;
      do {
        assert(pos < b.length && shift < 49);
        v = b[pos++];
        n += (v & 127) * 2 ** shift;
        shift += 7;
      } while (v & 128);
    }
    updates.push(n);
  }
  return { updates, fields_hex: b.subarray(pos).toString("hex") };
}
function* nodes(value) {
  if (Array.isArray(value)) {
    for (const v of value) yield* nodes(v);
  } else if (value && typeof value === "object") {
    yield value;
    for (const v of Object.values(value)) yield* nodes(v);
  }
}

// RFC 9204 field-section syntax only; values are independently decoded by
// Wireshark where possible, and cross-checked against the receiving peer.
// This parser deliberately does not use Surf's QPACK encoder or decoder.
export function qpackRepresentations(raw) {
  const b = Buffer.from(raw, "hex");
  let pos = 0;
  function integer(bits) {
    assert(pos < b.length, "truncated QPACK integer");
    const mask = (1 << bits) - 1;
    let n = b[pos++] & mask;
    if (n === mask) {
      let shift = 0,
        v;
      do {
        assert(pos < b.length && shift < 49, "invalid QPACK integer");
        v = b[pos++];
        n += (v & 127) * 2 ** shift;
        shift += 7;
      } while (v & 128);
    }
    return n;
  }
  function string(bits) {
    const huffman = !!(b[pos] & (1 << bits));
    const n = integer(bits);
    assert(pos + n <= b.length, "truncated QPACK string");
    pos += n;
    return huffman;
  }
  const requiredInsertCount = integer(8),
    deltaBase = integer(7),
    fields = [];
  while (pos < b.length) {
    const byte = b[pos];
    if (byte & 128)
      fields.push({
        kind: byte & 64 ? "indexed-static" : "indexed-dynamic",
        index: integer(6),
      });
    else if (byte & 64) {
      const field = {
        kind: byte & 16 ? "literal-static-name" : "literal-dynamic-name",
        never_index: !!(byte & 32),
        index: integer(4),
      };
      field.value_huffman = string(7);
      fields.push(field);
    } else if (byte & 32) {
      const field = { kind: "literal-name", never_index: !!(byte & 16) };
      field.name_huffman = string(3);
      field.value_huffman = string(7);
      fields.push(field);
    } else if (byte & 16)
      fields.push({ kind: "indexed-post-base", index: integer(4) });
    else {
      const field = {
        kind: "literal-post-base-name",
        never_index: !!(byte & 8),
        index: integer(3),
      };
      field.value_huffman = string(7);
      fields.push(field);
    }
  }
  return {
    required_insert_count: requiredInsertCount,
    delta_base: deltaBase,
    fields,
  };
}

function decodeCase(directory) {
  const server = read(join(directory, "server.json")),
    browser = read(join(directory, "browser.json"));
  const requests = lines(join(directory, "requests.jsonl"));
  const labels = ["browser", "surf-preset", "surf-exact-input"];
  const recorded = Object.fromEntries(
    labels.map((label) => [label, requests.filter((r) => r.label === label)]),
  );
  for (const label of labels)
    assert.equal(
      recorded[label].length,
      11,
      `${directory}: ${label} request count`,
    );
  const packets = read(join(directory, "wireshark.json")),
    groups = new Map();
  for (const packet of packets) {
    const layers = packet._source.layers,
      transport = layers[server.protocol === "h2" ? "tcp" : "udp"];
    const prefix = server.protocol === "h2" ? "tcp" : "udp";
    if (!transport || Number(transport[prefix + ".dstport"]) !== server.port)
      continue;
    const port = transport[prefix + ".srcport"];
    let group = groups.get(port);
    if (!group) {
      group = {
        port,
        headers: [],
        settings: [],
        frames: [],
        encoder_fragments: [],
        decoder_fragments: [],
        unidirectional_types: [],
        unidirectional_streams: {},
        priorities: [],
      };
      groups.set(port, group);
    }
    if (server.protocol === "h3")
      for (const n of nodes(layers.quic)) {
        const id = Number(n["quic.stream.stream_id"]);
        if (
          id % 4 === 2 &&
          n["quic.stream_data"] &&
          !Number(n["quic.stream.offset"] || 0)
        ) {
          const type = parseInt(n["quic.stream_data"].slice(0, 2), 16);
          if ([0, 2, 3].includes(type))
            group.unidirectional_streams[id] ??= type;
        }
      }
    for (const n of nodes(
      layers[server.protocol === "h2" ? "http2" : "http3"],
    )) {
      if (server.protocol === "h2") {
        if (n["http2.type"] !== undefined)
          group.frames.push({
            type: Number(n["http2.type"]),
            stream: Number(n["http2.streamid"]),
            flags: n["http2.flags"],
            ...(n["http2.stream_dependency"] !== undefined
              ? {
                  dependency: Number(n["http2.stream_dependency"]),
                  weight: Number(n["http2.headers.weight_real"]),
                }
              : {}),
          });
        if (n["http2.settings"]) group.settings.push(n["http2.settings"]);
        if (n["http2.type"] === "1")
          group.headers.push({
            stream: Number(n["http2.streamid"]),
            block: hex(n["http2.headers"]),
            fields: many(n["http2.header"]).map((f) => ({
              name: f["http2.header.name"],
              value: f["http2.header.value"],
            })),
            representations: many(n["http2.header"]).map((f) => ({
              kind: f["http2.header.repr"],
              index: f["http2.header.index"],
            })),
          });
      } else {
        if (n["http3.frame_type"] !== undefined) {
          const frame = {
            type: n["http3.frame_type"],
            stream: Number(n["http3.frame_streamid"]),
            length: Number(n["http3.frame_length"]),
            payload_hex: hex(n["http3.frame_payload"]),
          };
          group.frames.push(frame);
          if (BigInt(frame.type) === 1n)
            group.headers.push({
              stream: frame.stream,
              block: frame.payload_hex,
              fields: many(n["http3.headers.header"]).map((f) => ({
                name: f["http3.header.header.name"],
                value: f["http3.headers.header.value"],
              })),
            });
        }
        if (n["http3.settings"])
          group.settings.push(
            many(n["http3.settings"]).map((s) => ({
              id: s["http3.settings.id"],
              value: s["http3.settings.value"],
            })),
          );
        if (n["http3.qpack.encoder"])
          group.encoder_fragments.push(hex(n["http3.qpack.encoder"]));
        if (n["http3.qpack.decoder"])
          group.decoder_fragments.push(hex(n["http3.qpack.decoder"]));
        if (n["http3.stream_uni_type"])
          group.unidirectional_types.push(n["http3.stream_uni_type"]);
        if (n["http3.priority_update_element_id"] !== undefined)
          group.priorities.push({
            stream: Number(n["http3.priority_update_element_id"]),
            value: n["http3.priority_update_field_value"],
          });
      }
    }
  }
  // Fresh connections run sequentially: browser, preset, exact-input. Ignore
  // unrelated attempts without HTTP headers; reject ambiguity or fallback.
  const connections = [...groups.values()].filter((g) => g.headers.length);
  assert.equal(
    connections.length,
    3,
    `${directory}: expected three HTTP connections`,
  );
  let independent = 0,
    undecoded = 0;
  const captures = {};
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i],
      g = connections[i],
      seen = new Set();
    assert.equal(
      g.headers.length,
      11,
      `${directory}: ${label} Wireshark HEADERS count`,
    );
    g.headers = g.headers.map((h) => {
      const r = recorded[label].find((r) => (r.stream_id || 0) === h.stream);
      assert(r, `${label}: missing stream ${h.stream}`);
      assert(!seen.has(h.stream), "duplicate stream");
      seen.add(h.stream);
      if (h.fields.length) {
        assert.deepEqual(
          h.fields,
          r.fields,
          `${directory}: ${label} ${r.path}: peer/Wireshark disagree`,
        );
        independent++;
      } else undecoded++;
      if (server.protocol === "h2")
        assert.equal(h.block, r.header_block_hex, "raw HPACK bytes disagree");
      const qpack =
        server.protocol === "h3" ? qpackRepresentations(h.block) : undefined;
      if (qpack)
        assert.equal(
          qpack.fields.length,
          r.fields.length,
          `${label} ${r.path}: QPACK field count`,
        );
      return {
        ...h,
        path: r.path,
        peer_fields: r.fields,
        ...(server.protocol === "h2" ? { hpack: hpackUpdates(h.block) } : {}),
        ...(qpack ? { qpack } : {}),
      };
    });
    captures[label] = g;
  }
  const rows = captures.browser.headers.map((b, i) => {
    const exact = captures["surf-exact-input"].headers[i],
      preset = captures["surf-preset"].headers[i];
    assert.equal(b.path, exact.path);
    assert.equal(b.path, preset.path);
    return {
      path: b.path,
      exact_fields_equal: equal(b.peer_fields, exact.peer_fields),
      exact_block_equal: b.block === exact.block,
      ...(server.protocol === "h2"
        ? {
            exact_hpack_fields_equal:
              b.hpack.fields_hex === exact.hpack.fields_hex,
          }
        : {}),
      browser_bytes: b.block.length / 2,
      exact_bytes: exact.block.length / 2,
      preset_bytes: preset.block.length / 2,
      preset_fields_equal: equal(b.peer_fields, preset.peer_fields),
    };
  });
  const pcap = readFileSync(join(directory, "wire.pcap"));
  return {
    schema: 1,
    browser: browser.browser,
    protocol: server.protocol,
    server_capacity: server.capacity,
    browser_metadata: browser.metadata,
    captured_at: browser.captured_at,
    browser_flags: browser.flags.map((flag) =>
      flag.startsWith("--user-data-dir=")
        ? "--user-data-dir=TEMPORARY_PROFILE"
        : flag === browser.metadata?.capabilities?.["moz:profile"]
          ? "TEMPORARY_PROFILE"
          : flag,
    ),
    browser_prefs: browser.prefs,
    pcap_sha256: createHash("sha256").update(pcap).digest("hex"),
    independent_decoded_sections: independent,
    independent_undecoded_sections: undecoded,
    comparison: rows,
    captures,
  };
}

const summaries = [];
for (const name of readdirSync(root).sort()) {
  if (!/^(chrome|firefox)-h[23]-\d+$/.test(name)) continue;
  const result = decodeCase(join(root, name));
  writeFileSync(
    join(output, name + ".json"),
    JSON.stringify(result, null, 2) + "\n",
  );
  if (args.fixtures) {
    mkdirSync(args.fixtures, { recursive: true });
    const { captures, ...metadata } = result;
    const control = Object.fromEntries(
      Object.entries(captures).map(([label, capture]) => {
        const { headers, port, frames, ...rest } = capture;
        return [
          label,
          {
            ...rest,
            frames: frames.filter((f) => ![0, 1].includes(Number(f.type))),
          },
        ];
      }),
    );
    const requests = captures.browser.headers.map((h) => ({
      label: "browser",
      protocol: result.protocol,
      method: "GET",
      path: h.path,
      stream_id: h.stream,
      fields: h.peer_fields,
      header_block_hex: h.block,
      independent_fields_decoded: h.fields.length > 0,
      ...(h.hpack ? { hpack: h.hpack } : { qpack: h.qpack }),
    }));
    writeFileSync(
      join(args.fixtures, name + ".json"),
      JSON.stringify({ ...metadata, control, requests }, null, 2) + "\n",
    );
  }
  summaries.push({
    case: name,
    decoded: result.independent_decoded_sections,
    undecoded: result.independent_undecoded_sections,
    fields_equal: result.comparison.filter((r) => r.exact_fields_equal).length,
    blocks_equal: result.comparison.filter((r) => r.exact_block_equal).length,
    ...(result.protocol === "h2"
      ? {
          hpack_fields_equal: result.comparison.filter(
            (r) => r.exact_hpack_fields_equal,
          ).length,
        }
      : {}),
    browser_bytes: result.comparison.map((r) => r.browser_bytes),
    surf_bytes: result.comparison.map((r) => r.exact_bytes),
  });
}
writeFileSync(
  join(output, "summary.json"),
  JSON.stringify(summaries, null, 2) + "\n",
);
console.log(JSON.stringify(summaries, null, 2));
