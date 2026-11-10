import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { launchBrowser } from "./browser.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
if (args.diagnostic !== "true")
  throw Error(
    "This helper forces browser protocol/UA settings. Use native-endpoint.mjs for ordinary browser references; --diagnostic=true explicitly selects diagnostic references.",
  );
assert(
  args.out,
  "use --out=NEW_PRIVATE_DIRECTORY [--url=https://tls.peet.ws/api/all] [--os=windows|macos]",
);
const directory = resolve(args.out);
mkdirSync(directory, { mode: 0o700 });
const profile = mkdtempSync(join(directory, "profile-"));
const executable = "/Applications/Firefox.app/Contents/MacOS/firefox";
const version = spawnSync(executable, ["--version"], { encoding: "utf8" });
const major = version.stdout.match(/Firefox (\d+)/)?.[1];
assert(major, "cannot determine installed Firefox version");
const os = args.os || "windows";
const protocol = args.protocol || "h2";
const endpoint = new URL(args.url || "https://tls.peet.ws/api/all");
assert(["h1", "h2", "h3"].includes(protocol));
assert(["windows", "macos"].includes(os));
const prefs = {
  "remote.prefs.recommended": false,
  "devtools.jsonview.enabled": false,
  "browser.shell.checkDefaultBrowser": false,
  "browser.startup.page": 0,
  "network.proxy.type": 0,
  "network.http.http3.enable": protocol === "h3",
  "network.http.http2.enabled": protocol !== "h1",
};
if (os === "windows")
  prefs["general.useragent.override"] =
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`;
if (protocol === "h3")
  Object.assign(prefs, {
    "network.http.http3.alt-svc-mapping-for-testing": `${endpoint.hostname};h3=":${endpoint.port || "443"}"`,
    "network.http.http3.force-use-alt-svc-mapping-for-testing": true,
  });
writeFileSync(
  join(profile, "user.js"),
  Object.entries(prefs)
    .map(
      ([key, value]) =>
        `user_pref(${JSON.stringify(key)}, ${JSON.stringify(value)});`,
    )
    .join("\n") + "\n",
  { mode: 0o600 },
);
const flags = [
  "--headless",
  "--no-remote",
  "--profile",
  profile,
  "--remote-debugging-port=0",
  "about:blank",
];
const browser = await launchBrowser(
  executable,
  flags,
  /WebDriver BiDi listening on (ws:\/\/127\.0\.0\.1:\d+)/,
);
let metadata;
try {
  metadata = await browser.send("session.new", {
    capabilities: { alwaysMatch: { acceptInsecureCerts: false } },
  });
  const tree = await browser.send("browsingContext.getTree");
  const context = tree.contexts[0].context;
  await browser.send("browsingContext.navigate", {
    context,
    url: endpoint.href,
    wait: "complete",
  });
  const evaluation = await browser.send("script.evaluate", {
    expression: "document.body.textContent",
    target: { context },
    awaitPromise: true,
  });
  assert.equal(evaluation.type, "success", JSON.stringify(evaluation));
  const response = JSON.parse(evaluation.result.value);
  if (protocol === "h3") assert.equal(response.protocol, "http3");
  else
    assert.equal(response.http_version, protocol === "h2" ? "h2" : "HTTP/1.1");

  assert(
    protocol !== "h2" || (response.tls && response.http2),
    "endpoint must observe the browser TLS and HTTP/2 connection",
  );
  if (os === "windows" && protocol !== "h3")
    assert.equal(response.user_agent, prefs["general.useragent.override"]);
  writeFileSync(
    join(directory, "browser-endpoint.json"),
    JSON.stringify(response, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.log(
    JSON.stringify({
      complete: true,
      browser: metadata.capabilities.browserVersion,
      os,
      directory,
    }),
  );
} finally {
  await browser.close("browser.close");
  writeFileSync(join(directory, "browser.log"), browser.logs(), {
    mode: 0o600,
  });
  writeFileSync(
    join(directory, "browser.json"),
    JSON.stringify(
      { metadata, flags, prefs, captured_at: new Date().toISOString() },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
}
