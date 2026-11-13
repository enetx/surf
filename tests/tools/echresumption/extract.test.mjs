import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import {
  analysisKeyLog,
  chromePair,
  clientHello,
  innerRecords,
  tsharkPair,
  quicEvidence,
} from "./extract.mjs";

const ref = JSON.parse(
  readFileSync(
    new URL(
      "../../testdata/wire/ech/resumption/native/firefox-160-quic-1.json",
      import.meta.url,
    ),
  ),
);
const outer = Buffer.from(ref.outer, "base64"),
  inner = Buffer.from(ref.inner, "base64");
const server = Buffer.from(ref.server_hello, "base64"),
  ee = Buffer.from([8, 0, 0, 2, 0, 0]);
const raw = (b) => [b.toString("hex"), 0, b.length, 0, 0];
const b64 = (b) => b.toString("base64");
const recordLine = `UTLS_ECH_INNER_CLIENT_HELLO ${clientHello(outer).random.toString("hex")} ${inner.toString("hex")}\n`;
const hs = (b, decoded = {}) => ({
  "tls.handshake_raw": raw(b),
  "tls.handshake": decoded,
});

test("Surf key log associates actual send attempts with wire randoms", () => {
  const records = innerRecords(
    "# capture\nCLIENT_RANDOM ignored ignored\n" + recordLine + recordLine,
  );
  assert.equal(records.length, 2);
  assert.deepEqual(records[0].inner, inner);
  assert.throws(() => innerRecords("UTLS_ECH_INNER_CLIENT_HELLO zz 00"));
  assert.throws(() => innerRecords(recordLine.trimEnd() + " extra"));
  assert.throws(() => clientHello(inner.subarray(1)));
  assert.throws(() => clientHello(inner.subarray(0, 100)));
});

test("analysis aliases retain original traffic secrets and reject conflicts", () => {
  const a = clientHello(outer).random.toString("hex"),
    b = clientHello(inner).random.toString("hex");
  const source = `# private\nCLIENT_EARLY_TRAFFIC_SECRET ${a} abcd\nSERVER_HANDSHAKE_TRAFFIC_SECRET ${b} def0\nECH_SECRET arbitrary preserved\n`;
  const result = analysisKeyLog(source, [ref]);
  assert(result.startsWith(source));
  assert(result.includes(`CLIENT_EARLY_TRAFFIC_SECRET ${b} abcd\n`));
  assert(result.includes(`SERVER_HANDSHAKE_TRAFFIC_SECRET ${a} def0\n`));
  assert.equal(analysisKeyLog(result, [ref]), result);
  assert.throws(() =>
    analysisKeyLog(source + `CLIENT_EARLY_TRAFFIC_SECRET ${b} aaaa\n`, [ref]),
  );
});

test("TShark extraction keeps coalesced handshakes and rejects ambiguous pairs", () => {
  const packets = [
    hs(outer.subarray(0, 38)), // Earlier incomplete CRYPTO fragment.
    {
      arbitrary: [
        hs(outer),
        {
          "tls.handshake_raw": [raw(server), raw(ee)],
          "tls.handshake": [{}, {}],
        },
      ],
    },
  ];
  const pair = tsharkPair(packets, innerRecords(recordLine));
  assert.equal(pair.inner, ref.inner);
  assert.equal(pair.outer, ref.outer);
  assert.equal(pair.serverHello, ref.server_hello);
  assert.equal(pair.encryptedExtensions, b64(ee));
  assert.throws(() => tsharkPair(packets, []));
  const changed = Buffer.from(server);
  changed[10] ^= 1;
  assert.throws(() =>
    tsharkPair([...packets, hs(changed)], innerRecords(recordLine)),
  );
  assert.throws(() =>
    tsharkPair(
      [{ "tls.handshake_raw": [raw(server), raw(ee)], "tls.handshake": {} }],
      [],
    ),
  );
});

test("NSS expansion restores outer session ID and contiguous references", () => {
  const parsed = clientHello(inner),
    publicHello = clientHello(outer);
  const tree = Object.fromEntries(
    [
      ["version", inner.subarray(4, 6)],
      ["random", parsed.random],
      [
        "cipher_suites_length",
        Buffer.from([parsed.ciphers.length >> 8, parsed.ciphers.length & 255]),
      ],
      ["ciphersuites", parsed.ciphers],
      ["comp_methods_length", Buffer.from([parsed.compression.length])],
      ["comp_methods", parsed.compression],
    ].map(([name, value]) => ["tls.handshake." + name + "_raw", raw(value)]),
  );
  let compressed = false;
  tree["tls.handshake.extension_raw"] = [...parsed.extensions].map(
    ([id, value]) => {
      if (
        !compressed &&
        publicHello.extensions.has(id) &&
        publicHello.extensions.get(id).equals(value)
      ) {
        compressed = true;
        return raw(Buffer.from([0xfd, 0, 0, 3, 2, id >> 8, id & 255]));
      }
      return raw(value);
    },
  );
  assert(compressed);
  const decoded = {
    "tls.handshake.extension": { "tls.ech.payload_tree": tree },
  };
  assert.equal(
    tsharkPair([hs(outer, decoded), hs(server), hs(ee)]).inner,
    ref.inner,
  );
  assert.throws(() => tsharkPair([hs(outer), hs(server), hs(ee)]));
  tree["tls.handshake.extension_raw"][0] = raw(
    Buffer.from([0xfd, 0, 0, 3, 2, 0xab, 0xcd]),
  );
  assert.throws(() => tsharkPair([hs(outer, decoded), hs(server), hs(ee)]));
});

function log(events) {
  const types = Object.fromEntries(
    [...new Set(events.map(([name]) => name))].map((name, i) => [name, i]),
  );
  return {
    constants: { logEventTypes: types },
    events: events.map(([name, params]) => ({
      source: { id: 7 },
      type: types[name],
      params,
    })),
  };
}

test("native NetLog extraction authenticates complete CRYPTO streams without assuming UDP source dependencies", () => {
  const input = log([
    ["SSL_ENCRYPTED_CLIENT_HELLO", { bytes: ref.inner }],
    [
      "QUIC_SESSION_CRYPTO_FRAME_RECEIVED",
      {
        encryption_level: "ENCRYPTION_INITIAL",
        offset: 10,
        bytes: b64(server.subarray(10)),
      },
    ],
    [
      "QUIC_SESSION_CRYPTO_FRAME_RECEIVED",
      {
        encryption_level: "ENCRYPTION_INITIAL",
        offset: 0,
        bytes: b64(server.subarray(0, 20)),
      },
    ],
    [
      "QUIC_SESSION_CRYPTO_FRAME_RECEIVED",
      { encryption_level: "ENCRYPTION_HANDSHAKE", offset: 0, bytes: b64(ee) },
    ],
    ["QUIC_SESSION_STREAM_FRAME_SENT", { stream_id: 2, length: 12 }],
    ["QUIC_SESSION_STREAM_FRAME_SENT", { stream_id: 0, length: 478 }],
    ["QUIC_SESSION_PACKET_SENT", { encryption_level: "ENCRYPTION_ZERO_RTT" }],
    [
      "QUIC_SESSION_PACKET_SENT",
      { encryption_level: "ENCRYPTION_FORWARD_SECURE" },
    ],
  ]);
  const pair = chromePair(input, 7, "quic", outer);
  assert.equal(pair.serverHello, ref.server_hello);
  assert.deepEqual(pair.wire, {
    earlyPackets: 1,
    earlyControlPackets: 1,
    earlyRequestPackets: 1,
    source: 7,
  });
  const missing = structuredClone(input);
  missing.events.splice(2, 1);
  assert.throws(() => chromePair(missing, 7, "quic", outer));
  const conflicting = structuredClone(input);
  conflicting.events[2].params.bytes = b64(Buffer.alloc(20));
  assert.throws(() => chromePair(conflicting, 7, "quic", outer));
});

test("TCP NetLog extraction does not mistake NewSessionTicket for EncryptedExtensions", () => {
  const input = log([
    ["SSL_ENCRYPTED_CLIENT_HELLO", { bytes: ref.inner }],
    ["SSL_HANDSHAKE_MESSAGE_SENT", { bytes: ref.outer }],
    ["SSL_HANDSHAKE_MESSAGE_RECEIVED", { bytes: ref.server_hello }],
    ["SSL_HANDSHAKE_MESSAGE_RECEIVED", { bytes: b64(ee) }],
    [
      "SSL_HANDSHAKE_MESSAGE_RECEIVED",
      { bytes: b64(Buffer.from([4, 0, 0, 0])) },
    ],
  ]);
  assert.equal(chromePair(input, 7, "tcp").encryptedExtensions, b64(ee));
  assert.throws(() => chromePair(input, 8, "tcp"));
});

test("wire evidence handles coalescing, implicit STREAM lengths, control-only early data and QUIC v2", () => {
  const packet = (version, type, frames) => ({
    "quic.version": version,
    "quic.long.packet_type": type,
    "quic.frame": frames,
  });
  const control = { "quic.stream.stream_id": "2", "quic.stream.length": "31" };
  const request = {
    "quic.stream.stream_id": "0",
    "quic.stream_data_raw": ["abcd", 0, 2, 0, 0],
  };
  const packets = [
    { quic: [packet("1", "0", []), packet("1", "1", [control, request])] },
    { quic: packet("0x6b3343cf", "2", control) },
  ];
  assert.deepEqual(quicEvidence(packets), {
    earlyPackets: 2,
    earlyControlPackets: 2,
    earlyRequestPackets: 1,
  });
  assert.deepEqual(quicEvidence([{ quic: packet("1", "1", control) }]), {
    earlyPackets: 1,
    earlyControlPackets: 1,
    earlyRequestPackets: 0,
  });
  assert.throws(() => quicEvidence([packet("1", "1", undefined)]));
  assert.throws(() =>
    quicEvidence([packet("1", "1", { "quic.stream.stream_id": "0" })]),
  );
  const v2 = packet("0x6b3343cf", "2", control);
  delete v2["quic.long.packet_type"];
  v2["quic.long.packet_type_v2"] = "2";
  assert.deepEqual(quicEvidence([v2]), {
    earlyPackets: 1,
    earlyControlPackets: 1,
    earlyRequestPackets: 0,
  });
});

test("wire evidence rejects a kernel-truncated offload frame even with parsed early STREAM data", () => {
  const packet = {
    _source: {
      layers: {
        frame: { "frame.len": "2546", "frame.cap_len": "1530" },
        quic: {
          "quic.version": "1",
          "quic.long.packet_type": "1",
          "quic.frame": {
            "quic.stream.stream_id": "0",
            "quic.stream.length": "400",
          },
        },
      },
    },
  };

  assert.throws(() => quicEvidence([packet]), /truncated capture frame/);

  packet._source.layers.frame["frame.cap_len"] = "2546";
  assert.deepEqual(quicEvidence([packet]), {
    earlyPackets: 1,
    earlyControlPackets: 0,
    earlyRequestPackets: 1,
  });
});
