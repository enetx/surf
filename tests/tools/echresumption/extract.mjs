// Private capture extraction. Output still contains live PSKs: pass it through
// the Go verifier/redactor before adding any reference to the repository.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

const bytes = (s) => Buffer.from(s, "base64");
const encoded = (b) => b.toString("base64");
const list = (v) => (Array.isArray(v) ? v : [v]);
const rawList = (v) => (Array.isArray(v[0]) ? v : [v]);

function message(raw, type) {
  assert(
    raw.length >= 4 &&
      raw[0] === type &&
      raw.readUIntBE(1, 3) + 4 === raw.length,
    "invalid handshake framing",
  );
  return raw;
}

export function clientHello(raw) {
  message(raw, 1);
  let at = 38;
  const take = (n) => {
    assert(at + n <= raw.length, "truncated ClientHello");
    const value = raw.subarray(at, at + n);
    at += n;
    return value;
  };
  const vector = (width) => take(take(width).readUIntBE(0, width));
  const sessionID = vector(1),
    ciphers = vector(2),
    compression = vector(1);
  const extensionBytes = vector(2);
  assert(
    at === raw.length && sessionID.length <= 32 && ciphers.length % 2 === 0,
    "invalid ClientHello vectors",
  );
  const extensions = new Map();
  for (let i = 0; i < extensionBytes.length; ) {
    assert(i + 4 <= extensionBytes.length, "truncated extension header");
    const id = extensionBytes.readUInt16BE(i),
      n = extensionBytes.readUInt16BE(i + 2);
    assert(
      i + n + 4 <= extensionBytes.length && !extensions.has(id),
      "invalid/duplicate extension",
    );
    extensions.set(id, extensionBytes.subarray(i, i + n + 4));
    i += n + 4;
  }
  return {
    sessionID,
    ciphers,
    compression,
    extensions,
    random: raw.subarray(6, 38),
  };
}

export function innerRecords(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] !== "UTLS_ECH_INNER_CLIENT_HELLO") continue;
    assert(
      parts.length === 3 &&
        /^[0-9a-f]{64}$/i.test(parts[1]) &&
        /^(?:[0-9a-f]{2})+$/i.test(parts[2]),
      "invalid private inner key-log line",
    );
    const inner = Buffer.from(parts[2], "hex");
    clientHello(inner);
    records.push({ outerRandom: parts[1].toLowerCase(), inner });
  }
  return records;
}

// Wireshark and TLS engines may index ECH secrets by different randoms. Add
// lookup aliases only: never derive or alter traffic key material. Preserve the
// original file and use this output solely for analysis.
export function analysisKeyLog(text, pairs) {
  const aliases = new Map();
  for (const pair of pairs) {
    const outer = clientHello(bytes(pair.outer)).random.toString("hex");
    const inner = clientHello(bytes(pair.inner)).random.toString("hex");
    for (const [from, to] of [
      [outer, inner],
      [inner, outer],
    ]) {
      assert(
        !aliases.has(from) || aliases.get(from) === to,
        "ambiguous ECH random mapping",
      );
      aliases.set(from, to);
    }
  }
  const seen = new Map(),
    added = [];
  const traffic =
    /^(?:(?:CLIENT|SERVER)_(?:EARLY_TRAFFIC_SECRET|HANDSHAKE_TRAFFIC_SECRET|TRAFFIC_SECRET_\d+)|(?:EARLY_)?EXPORTER_SECRET)$/;
  const lines = text.split(/\r?\n/).map((x) => x.trim().split(/\s+/));
  function remember(label, random, secret) {
    const key = label + " " + random.toLowerCase();
    assert(
      !seen.has(key) || seen.get(key) === secret,
      "conflicting key-log alias",
    );
    seen.set(key, secret);
  }
  for (const [label, random, secret] of lines)
    if (traffic.test(label)) remember(label, random, secret);
  for (const [label, random, secret] of lines) {
    if (!traffic.test(label) || !aliases.has(random.toLowerCase())) continue;
    const alias = aliases.get(random.toLowerCase()),
      key = label + " " + alias;
    if (!seen.has(key)) {
      added.push(`${label} ${alias} ${secret}`);
      remember(label, alias, secret);
    } else assert(seen.get(key) === secret, "conflicting ECH traffic secrets");
  }
  return text.trimEnd() + "\n" + (added.length ? added.join("\n") + "\n" : "");
}

function reassemble(chunks) {
  const sorted = chunks.toSorted((a, b) => a.offset - b.offset);
  const result = [];
  for (const chunk of sorted) {
    const data = bytes(chunk.bytes);
    assert(
      Number.isSafeInteger(chunk.offset) &&
        chunk.offset >= 0 &&
        chunk.offset <= result.length,
      "missing CRYPTO bytes",
    );
    for (let i = 0; i < data.length; i++) {
      const n = chunk.offset + i;
      assert(
        n >= result.length || result[n] === data[i],
        "conflicting CRYPTO retransmission",
      );
      result[n] = data[i];
    }
  }
  const raw = Buffer.from(result),
    messages = [];
  for (let at = 0; at < raw.length; ) {
    assert(at + 4 <= raw.length, "truncated CRYPTO handshake header");
    const n = raw.readUIntBE(at + 1, 3) + 4;
    assert(at + n <= raw.length, "truncated CRYPTO handshake");
    messages.push(raw.subarray(at, at + n));
    at += n;
  }
  return messages;
}

export function chromePair(log, source, transport, quicOuter) {
  const types = new Map(
    Object.entries(log.constants.logEventTypes).map(([k, v]) => [v, k]),
  );
  const direct = [],
    crypto = new Map(),
    inners = [];
  let pending = [],
    earlyPackets = 0,
    earlyControlPackets = 0,
    earlyRequestPackets = 0;
  for (const event of log.events.filter((x) => x.source.id === source)) {
    const type = types.get(event.type),
      p = event.params ?? {};
    if (type === "SSL_ENCRYPTED_CLIENT_HELLO") inners.push(bytes(p.bytes));
    if (
      type === "SSL_HANDSHAKE_MESSAGE_RECEIVED" ||
      type === "SSL_HANDSHAKE_MESSAGE_SENT"
    )
      direct.push({ sent: type.endsWith("_SENT"), raw: bytes(p.bytes) });
    if (type === "QUIC_SESSION_CRYPTO_FRAME_RECEIVED" && p.bytes) {
      if (!crypto.has(p.encryption_level)) crypto.set(p.encryption_level, []);
      crypto.get(p.encryption_level).push(p);
    }
    if (type === "QUIC_SESSION_STREAM_FRAME_SENT") pending.push(p);
    if (type === "QUIC_SESSION_PACKET_SENT") {
      if (p.encryption_level === "ENCRYPTION_ZERO_RTT") {
        earlyPackets++;
        if (pending.some((f) => f.stream_id % 4 === 2 && f.length > 0))
          earlyControlPackets++;
        if (pending.some((f) => f.stream_id % 4 === 0 && f.length > 0))
          earlyRequestPackets++;
      }
      pending = [];
    }
  }
  assert(
    inners.length === 1,
    "select exactly one normal ECH handshake (HRR needs its own transcript)",
  );
  const received =
    transport === "tcp"
      ? direct.filter((m) => !m.sent).map((m) => m.raw)
      : [...crypto.values()].flatMap(reassemble);
  const select = (type) => {
    const matching = received.filter((m) => m[0] === type);
    assert(matching.length === 1, "ambiguous or missing server handshake");
    return encoded(message(matching[0], type));
  };
  const outer =
    transport === "tcp"
      ? direct.find((m) => m.sent && m.raw[0] === 1)?.raw
      : quicOuter;
  clientHello(outer);
  clientHello(inners[0]);
  return {
    outer: encoded(outer),
    inner: encoded(inners[0]),
    serverHello: select(2),
    encryptedExtensions: select(8),
    wire: { earlyPackets, earlyControlPackets, earlyRequestPackets, source },
  };
}

function walk(node, visit) {
  if (!node || typeof node !== "object") return;
  visit(node);
  for (const value of Object.values(node)) walk(value, visit);
}

export function expandNSS(outer, hello) {
  const extensions = list(hello["tls.handshake.extension"]);
  const inner = extensions.find((e) => e["tls.ech.payload_tree"])?.[
    "tls.ech.payload_tree"
  ];
  assert(inner, "Wireshark did not decrypt NSS ECH");
  const publicHello = clientHello(outer),
    expanded = [];
  for (const record of rawList(inner["tls.handshake.extension_raw"])) {
    const raw = Buffer.from(record[0], "hex"),
      id = raw.readUInt16BE(0);
    assert(raw.readUInt16BE(2) + 4 === raw.length, "bad inner extension");
    if (id !== 0xfd00) {
      expanded.push(raw);
      continue;
    }
    assert(
      raw[4] === raw.length - 5 && raw[4] % 2 === 0,
      "bad outer references",
    );
    for (let i = 5; i < raw.length; i += 2) {
      const ref = publicHello.extensions.get(raw.readUInt16BE(i));
      assert(ref, "missing outer reference");
      expanded.push(ref);
    }
  }
  const field = (name) => Buffer.from(inner[name + "_raw"][0], "hex");
  const ext = Buffer.concat(expanded),
    n = Buffer.alloc(2);
  n.writeUInt16BE(ext.length);
  const body = Buffer.concat([
    field("tls.handshake.version"),
    field("tls.handshake.random"),
    Buffer.from([publicHello.sessionID.length]),
    publicHello.sessionID,
    ...[
      "cipher_suites_length",
      "ciphersuites",
      "comp_methods_length",
      "comp_methods",
    ].map((k) => field("tls.handshake." + k)),
    n,
    ext,
  ]);
  const header = Buffer.alloc(4);
  header[0] = 1;
  header.writeUIntBE(body.length, 1, 3);
  const raw = Buffer.concat([header, body]);
  clientHello(raw);
  return raw;
}

function tsharkMessages(packets) {
  const messages = [];
  walk(packets, (node) => {
    if (!node["tls.handshake_raw"] || !node["tls.handshake"]) return;
    const raw = rawList(node["tls.handshake_raw"]),
      decoded = list(node["tls.handshake"]);
    assert(raw.length === decoded.length, "use tshark --no-duplicate-keys");
    raw.forEach((r, i) => {
      const data = Buffer.from(r[0], "hex");
      // Wireshark may expose an incomplete handshake on an earlier CRYPTO
      // fragment as well as the final reassembled message. Only the latter
      // can participate in an authenticated reference.
      if (data.length < 4 || data.readUIntBE(1, 3) + 4 !== data.length) return;
      messages.push({ raw: data, decoded: decoded[i] });
    });
  });
  return messages;
}

function selectMessage(messages, type) {
  const matches = [
    ...new Map(
      messages
        .filter((m) => m.raw[0] === type)
        .map((m) => [m.raw.toString("hex"), m]),
    ).values(),
  ];
  assert(
    matches.length === 1,
    "select frames for exactly one client/server pair",
  );
  message(matches[0].raw, type);
  return matches[0];
}

export function wireOuter(packets) {
  return selectMessage(tsharkMessages(packets), 1).raw;
}

export function tsharkPair(packets, records) {
  const messages = tsharkMessages(packets);
  const client = selectMessage(messages, 1),
    outer = client.raw;
  const inner = records
    ? records.filter(
        (r) => r.outerRandom === clientHello(outer).random.toString("hex"),
      )
    : null;
  if (inner)
    assert(inner.length === 1, "missing/ambiguous Surf inner send attempt");
  return {
    outer: encoded(outer),
    inner: encoded(inner ? inner[0].inner : expandNSS(outer, client.decoded)),
    serverHello: encoded(selectMessage(messages, 2).raw),
    encryptedExtensions: encoded(selectMessage(messages, 8).raw),
  };
}

// Input must select one connection, including every early packet, and use
// tshark -T json -x --no-duplicate-keys. Count QUIC packets, not UDP datagrams.
export function quicEvidence(packets) {
  for (const packet of packets) {
    const frame = packet._source?.layers?.frame;
    if (!frame) continue;

    const captured = Number(frame["frame.cap_len"]),
      original = Number(frame["frame.len"]);
    assert(
      Number.isSafeInteger(captured) &&
        Number.isSafeInteger(original) &&
        original > 0 &&
        captured === original,
      "truncated capture frame cannot establish complete early-data evidence",
    );
  }

  let earlyPackets = 0,
    earlyControlPackets = 0,
    earlyRequestPackets = 0;
  walk(packets, (node) => {
    // Wireshark exposes RFC 9369's remapped type under a separate v2 field.
    const packetType =
      node["quic.long.packet_type_v2"] ?? node["quic.long.packet_type"];
    if (packetType === undefined) return;
    const version = Number(BigInt(node["quic.version"]));
    assert(version === 1 || version === 0x6b3343cf, "unsupported QUIC version");
    if (Number(packetType) !== (version === 1 ? 1 : 2))
      return;
    assert(node["quic.frame"], "early packet was not independently decrypted");
    earlyPackets++;
    let control = false,
      request = false;
    for (const frame of list(node["quic.frame"])) {
      if (frame["quic.stream.stream_id"] === undefined) continue;
      const id = BigInt(frame["quic.stream.stream_id"]);
      // STREAM without LEN consumes the remaining payload. Its raw length
      // remains available even when Wireshark omits quic.stream.length.
      const n =
        frame["quic.stream.length"] ?? frame["quic.stream_data_raw"]?.[2];
      assert(n !== undefined, "missing STREAM payload length (use -x)");
      if (Number(n) > 0 && id % 4n === 2n) control = true;
      if (Number(n) > 0 && id % 4n === 0n) request = true;
    }
    earlyControlPackets += Number(control);
    earlyRequestPackets += Number(request);
  });
  return { earlyPackets, earlyControlPackets, earlyRequestPackets };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const { values: v } = parseArgs({
    options: Object.fromEntries(
      [
        "netlog",
        "source",
        "transport",
        "outer",
        "outer-json",
        "packet-json",
        "keylog",
        "metadata",
        "out",
        "alias-pairs",
        "wire-json",
      ].map((name) => [name, { type: "string" }]),
    ),
  });
  const readJSON = (p) => JSON.parse(readFileSync(p, "utf8"));
  assert(v.out, "provide --out (private new file)");
  if (v["alias-pairs"]) {
    writeFileSync(
      v.out,
      analysisKeyLog(
        readFileSync(v.keylog, "utf8"),
        readJSON(v["alias-pairs"]),
      ),
      { mode: 0o600, flag: "wx" },
    );
  } else {
    const pair = v.netlog
      ? chromePair(
          readJSON(v.netlog),
          Number(v.source),
          v.transport,
          v["outer-json"]
            ? wireOuter(readJSON(v["outer-json"]))
            : v.outer && readFileSync(v.outer),
        )
      : tsharkPair(
          readJSON(v["packet-json"]),
          v.keylog && innerRecords(readFileSync(v.keylog, "utf8")),
        );
    const metadata = readJSON(v.metadata);
    const wire = v["wire-json"]
      ? quicEvidence(readJSON(v["wire-json"]))
      : (pair.wire ?? metadata.wire);
    writeFileSync(
      v.out,
      JSON.stringify([{ ...metadata, ...pair, wire }], null, 2) + "\n",
      { mode: 0o600, flag: "wx" },
    );
  }
}
