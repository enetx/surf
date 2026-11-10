import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { nativeFingerprint, parseEndpointJSON } from "./native-fingerprint.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(
  args.browser && args.surf && args.out,
  "use --browser=PRIVATE_BROWSER_DIRECTORY --surf=PRIVATE_SURF_DIRECTORY --out=REPORT.json",
);
const read = (p) => parseEndpointJSON(readFileSync(p, "utf8"));
const browserPath = join(args.browser, "browser-endpoint.json"),
  surfPath = join(args.surf, "surf-endpoint.json");
const meta = read(join(args.browser, "browser.json")),
  browser = read(browserPath),
  surf = read(surfPath);
assert.equal(browser.protocol, "http3");
assert.equal(surf.protocol, "http3");
const left = nativeFingerprint(browser),
  right = nativeFingerprint(surf);
const comparison = Object.fromEntries(
  Object.keys(left).map((key) => [
    key,
    {
      equal: JSON.stringify(left[key]) === JSON.stringify(right[key]),
      browser: left[key],
      surf: right[key],
    },
  ]),
);
const hash = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
writeFileSync(
  args.out,
  JSON.stringify(
    {
      schema: 1,
      browser:
        meta.metadata.capabilities?.browserVersion || meta.metadata.product,
      captured_at: meta.captured_at,
      method: meta.method,
      endpoint: meta.endpoint,
      attempts: meta.attempts,
      browser_response_sha256: hash(browserPath),
      surf_response_sha256: hash(surfPath),
      scope:
        "Ordinary browser navigation over public TLS and standard Alt-Svc. Endpoint-observed fingerprints, not a packet capture or a controlled loss/racing experiment. GREASE entropy and SCID values are normalized; version capabilities and brand headers are retained.",
      comparison,
    },
    null,
    2,
  ) + "\n",
);
