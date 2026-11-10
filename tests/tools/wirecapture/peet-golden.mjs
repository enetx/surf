import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(
  args.browser && args.surf && args.out,
  "use --browser=BROWSER_JSON --surf=SURF_JSON --out=NEW_GOLDEN [--report=SUMMARY_JSON]",
);
const bytes = (path) => readFileSync(path);
const browserBytes = bytes(args.browser),
  surfBytes = bytes(args.surf);
const browser = JSON.parse(browserBytes),
  surf = JSON.parse(surfBytes);
const number = (name) => Number(name.match(/\((\d+)\)$/)?.[1]);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const vector16 = (data) => Buffer.concat([u16(data.length), data]);
const integers = (values) => Buffer.concat(values.map(u16));
const fields = [
  "ip_version",
  "ttl",
  "df",
  "ecn",
  "window",
  "mss",
  "window_scale",
  "sack_permitted",
  "timestamps",
  "option_order",
  "payload_len",
  "packet_len",
];

function normalize(data) {
  assert(["h2", "HTTP/1.1"].includes(data.http_version));
  assert(
    data.user_agent.includes("Windows NT 10.0") &&
      data.user_agent.includes("Firefox/160.0"),
  );
  const tls = data.tls,
    ja3 = tls.ja3.split(","),
    peet = tls.peetprint.split("|");
  const extensions = tls.extensions.map((e) => ({ ...e, id: number(e.name) }));
  assert(extensions.every((e) => Number.isInteger(e.id)));
  assert.equal(extensions.map((e) => e.id).join("-"), ja3[2]);
  const signatureNames = extensions.find(
    (e) => e.id === 13,
  ).signature_algorithms;
  const signatures = peet[3].split("-").map(Number);
  assert.equal(signatureNames.length, signatures.length);
  const signatureIDs = Object.fromEntries(
    signatureNames.map((name, i) => [name, signatures[i]]),
  );
  let ech;
  const lines = extensions.map((e) => {
    let value;
    switch (e.id) {
      case 0:
        value = vector16(
          Buffer.concat([
            Buffer.from([0]),
            vector16(Buffer.from(e.server_name)),
          ]),
        ).toString("hex");
        break;
      case 10:
        value = e.supported_groups.map(number).join(" ");
        break;
      case 13:
        value = signatures.join(" ");
        break;
      case 11: {
        const points = Buffer.from(
          e.elliptic_curves_point_formats.map((v) => Number(v)),
        );
        value = Buffer.concat([Buffer.from([points.length]), points]).toString(
          "hex",
        );
        break;
      }
      case 16:
        value = vector16(
          Buffer.concat(
            e.protocols.map((p) =>
              Buffer.concat([Buffer.from([p.length]), Buffer.from(p)]),
            ),
          ),
        ).toString("hex");
        break;
      case 5: {
        const status = e.status_request;
        assert.equal(status.responder_id_list_length, 0);
        assert.equal(status.request_extensions_length, 0);
        value = Buffer.from([
          number(status.certificate_status_type),
          0,
          0,
          0,
          0,
        ]).toString("hex");
        break;
      }
      case 34: {
        const ids = e.signature_hash_algorithms.map((name) => {
          assert(name in signatureIDs);
          return signatureIDs[name];
        });
        value = vector16(integers(ids)).toString("hex");
        break;
      }
      case 43:
        value = peet[0].split("-").join(" ");
        break;
      case 27:
        value = e.algorithms.map(number).join(" ");
        break;
      case 45:
        value = Buffer.from([1, number(e.PSK_Key_Exchange_Mode)]).toString(
          "hex",
        );
        break;
      case 51:
        value = e.shared_keys
          .flatMap((share) =>
            Object.entries(share).map(
              ([name, hex]) => `${number(name)}:${hex.length / 2}`,
            ),
          )
          .join(" ");
        break;
      case 65037: {
        const raw = Buffer.from(e.data, "hex"),
          enc = raw.readUInt16BE(6),
          payload = raw.readUInt16BE(8 + enc);
        ech = {
          type: raw[0],
          kdf: raw.readUInt16BE(1),
          aead: raw.readUInt16BE(3),
          enc,
          payload,
        };
        assert.equal(ech.type, 0);
        assert.equal(ech.kdf, 1);
        assert([1, 3].includes(ech.aead));
        assert.equal(enc, 32);
        assert.equal(payload, 240);
        value = `type=${ech.type} kdf=${ech.kdf} enc=${enc} payload%16=${payload % 16}`;
        break;
      }
      case 18:
      case 23:
        value = "";
        break;
      default:
        assert.equal(typeof e.data, "string", `unhandled extension ${e.id}`);
        value = e.data;
    }
    return `ext ${e.id}: ${value}`.trimEnd();
  });
  lines.sort((a, b) =>
    a.split(":")[0].localeCompare(b.split(":")[0], "en", { usage: "sort" }),
  );
  // TLS 1.3 negotiation requires the legacy compression vector to be [0].
  // A separate local raw ClientHello capture cross-checks this browser layout.
  assert.equal(tls.tls_version_negotiated, "772");
  const hello = `extensions ${extensions.map((e) => e.id).join(",")}\nlegacy_version 0x${Number(ja3[0]).toString(16).padStart(4, "0")}\nsession_id ${tls.session_id.length / 2} bytes\ncipher_suites ${ja3[1].split("-").join(",")}\ncompression 00\n${lines.join("\n")}\n`;
  const shared = {
    hello,
    ech,
    ja3: tls.ja3_hash,
    ja4: tls.ja4,
    peetprint: tls.peetprint_hash,
    tcp_syn: Object.fromEntries(
      fields.map((key) => [key, data.tcpip.tcp_syn[key]]),
    ),
  };
  if (data.http_version === "HTTP/1.1")
    return {
      ...shared,
      navigation: data.http1.headers.join("\n") + "\n",
      headers: data.http1.headers,
    };
  const h2 = data.http2;
  const settings = h2.sent_frames.find((f) => f.frame_type === "SETTINGS");
  const window = h2.sent_frames.find(
    (f) => f.frame_type === "WINDOW_UPDATE" && !f.stream_id,
  );
  const headers = h2.sent_frames.find((f) => f.frame_type === "HEADERS");
  const ids = {
    HEADER_TABLE_SIZE: 1,
    ENABLE_PUSH: 2,
    MAX_CONCURRENT_STREAMS: 3,
    INITIAL_WINDOW_SIZE: 4,
    MAX_FRAME_SIZE: 5,
    MAX_HEADER_LIST_SIZE: 6,
    ENABLE_CONNECT_PROTOCOL: 8,
  };
  const settingsLine = settings.settings
    .map((setting) => {
      const [name, value] = setting.split(" = ");
      assert(name in ids);
      return `${ids[name]}=${value}`;
    })
    .join(" ");
  const flags = headers.flags.reduce(
    (value, flag) => value | parseInt(flag.match(/\(0x([\da-f]+)\)/i)[1], 16),
    0,
  );
  let headerLine = `HEADERS stream=${headers.stream_id} flags=0x${flags.toString(16)}`;
  if (headers.priority)
    headerLine += ` exclusive=${Boolean(headers.priority.exclusive)} dep=${headers.priority.depends_on} weight=${headers.priority.weight}`;
  const navigation = `SETTINGS ${settingsLine}\nWINDOW_UPDATE stream=0 increment=${window.increment}\n${headerLine}\n${headers.headers.join("\n")}\n`;
  return {
    ...shared,
    navigation,
    h2_fingerprint: h2.akamai_fingerprint,
    http2_frames: h2.sent_frames,
  };
}
assert.equal(surf.http_version, browser.http_version);
const protocol = browser.http_version === "h2" ? 2 : 1;
assert.deepEqual(
  surf[`http${protocol}`],
  browser[`http${protocol}`],
  "full HTTP endpoint report, including frames and ordered fields",
);
const b = normalize(browser),
  s = normalize(surf);
for (const key of [
  "hello",
  "navigation",
  "ja3",
  "ja4",
  "peetprint",
  "h2_fingerprint",
])
  assert.deepEqual(s[key], b[key], `browser/Surf mismatch: ${key}`);
writeFileSync(
  args.out,
  `# firefox-160-windows\n# Source: Firefox 160 on macOS with a Windows User-Agent override; https://tls.peet.ws/api/all\n# Browser response SHA-256: ${createHash("sha256").update(browserBytes).digest("hex")}\n\n## tcp client hello (h${protocol})\n${b.hello}\n## http/${protocol} navigation\n${b.navigation}`,
);
const report = {
  schema: 1,
  source:
    "Firefox 160.0 on macOS with Windows User-Agent override; direct browser navigation and Surf request to https://tls.peet.ws/api/all. This does not claim a Windows kernel TCP fingerprint.",
  browser_sha256: createHash("sha256").update(browserBytes).digest("hex"),
  surf_sha256: createHash("sha256").update(surfBytes).digest("hex"),
  matched: { tls: true, [`http${protocol}`]: true, ordered_headers: true },
  browser: b,
  surf: s,
};
if (args.report)
  writeFileSync(args.report, JSON.stringify(report, null, 2) + "\n");
console.log(
  JSON.stringify({
    matched: true,
    ja3: b.ja3,
    ja4: b.ja4,
    peetprint: b.peetprint,
    http2: b.h2_fingerprint,
  }),
);
