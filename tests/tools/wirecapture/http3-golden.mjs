import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(
  args.in && args.out,
  "use --in=BROWSER_HTTP3_ENDPOINT_JSON --out=NEW_REFERENCE_JSON",
);
const raw = readFileSync(args.in),
  data = JSON.parse(raw);
assert.equal(data.protocol, "http3");
const extensions = Object.fromEntries(
  data.tls.extensions.map((e) => [e.id, e.data]),
);
const parameters = extensions[57];
const headers = data.http3.headers;
const ua = Array.isArray(headers)
  ? headers.find((h) => h.name === "user-agent")?.value
  : headers["user-agent"];
assert(ua.includes("Windows NT 10.0") && ua.includes("Firefox/160.0"));
const values = {};
for (const parameter of parameters) {
  if (parameter.id === 15) values[15] = "AUTO";
  else if (parameter.id === 0xff02de1a) {
    assert.equal(parameter.value, "0x43e8");
    values[parameter.id] = 1000;
  } else values[parameter.id] = parameter.value;
}
const ech = extensions[65037];
const reference = {
  source: {
    browser: "Firefox 160.0",
    capture:
      "Independent installed Firefox on macOS; fresh profile with Windows User-Agent override and forced HTTP/3. No Windows kernel TCP claim.",
    endpoint: "https://fp.impersonate.pro/api/http3",
    sha256: createHash("sha256").update(raw).digest("hex"),
  },
  user_agent: ua,
  initial_packet_number: data.quic.initial_packet_number,
  client_connection_id_length: data.quic.client_connection_id_length,
  settings: data.http3.settings.map((s) => [s.id, s.value]),
  header_order: data.http3.header_order,
  transport_parameters: values,
  transport_parameter_order: parameters.map((p) => p.id),
  tls: {
    cipher_suites: data.tls.cipher_suites.map((c) => c.value),
    extensions: data.tls.extensions.map((e) => e.id).sort((a, b) => a - b),
    groups: extensions[10].groups.map((g) => g.value),
    signature_algorithms: extensions[13].algorithms.map((a) => a.value),
    versions: extensions[43].map((v) => v.value),
    key_shares: extensions[51].shares.map((s) => [s.group.value, s.key_length]),
    ech_cipher_suite: [
      ech.cipher_suite.kdf_id.value,
      ech.cipher_suite.aead_id.value,
    ],
    observed_ech_lengths: [ech.length],
    extension_bytes: {
      27: extensions[27].raw,
      28: Number(extensions[28]).toString(16).padStart(4, "0"),
      34: extensions[34].raw,
      65281: extensions[65281].raw,
    },
  },
};
writeFileSync(args.out, JSON.stringify(reference, null, 2) + "\n");
console.log(
  JSON.stringify({
    source: reference.source.browser,
    quic: true,
    windows_user_agent: true,
  }),
);
