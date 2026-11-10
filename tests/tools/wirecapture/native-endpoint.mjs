// Publicly trusted HTTPS only. No forced protocol, certificate bypass,
// resolver/proxy override, User-Agent override or headless browser mode.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { launchBrowser } from "./browser.mjs";
import { parseEndpointJSON } from "./native-fingerprint.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
assert(
  args.out && ["chrome", "firefox"].includes(args.browser),
  "use --browser=chrome|firefox --out=NEW_PRIVATE_DIRECTORY [--url=https://fp.impersonate.pro/api/http3]",
);
const directory = resolve(args.out);
mkdirSync(directory, { mode: 0o700 });
const profile = mkdtempSync(join(directory, "profile-"));
const endpoint = new URL(args.url || "https://fp.impersonate.pro/api/http3");
assert.equal(endpoint.protocol, "https:");
const firefox = args.browser === "firefox";
const flags = firefox
  ? [
      "--no-remote",
      "--profile",
      profile,
      "--remote-debugging-port=0",
      "about:blank",
    ]
  : [
      "--user-data-dir=" + profile,
      "--remote-debugging-port=0",
      "--no-first-run",
      "about:blank",
    ];
const prefs = firefox
  ? {
      "remote.prefs.recommended": false,
      "devtools.jsonview.enabled": false,
      "browser.shell.checkDefaultBrowser": false,
      "browser.startup.page": 0,
    }
  : {};
if (firefox)
  writeFileSync(
    join(profile, "user.js"),
    Object.entries(prefs)
      .map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`)
      .join("\n") + "\n",
    { mode: 0o600 },
  );
const browser = await launchBrowser(
  firefox
    ? "/Applications/Firefox.app/Contents/MacOS/firefox"
    : "/Applications/Chromium.app/Contents/MacOS/Chromium",
  flags,
  firefox
    ? /WebDriver BiDi listening on (ws:\/\/127\.0\.0\.1:\d+)/
    : /DevTools listening on (ws:\/\/[^\s]+)/,
);
let metadata, context, sessionId;
const attempts = [];
try {
  if (firefox) {
    metadata = await browser.send("session.new", {
      capabilities: { alwaysMatch: { acceptInsecureCerts: false } },
    });
    context = (await browser.send("browsingContext.getTree")).contexts[0]
      .context;
  } else {
    metadata = await browser.send("Browser.getVersion");
    const { targetId } = await browser.send("Target.createTarget", {
      url: "about:blank",
    });
    ({ sessionId } = await browser.send("Target.attachToTarget", {
      targetId,
      flatten: true,
    }));
    await browser.send("Page.enable", {}, sessionId);
  }
  let response;
  for (let n = 0; n < 8; n++) {
    if (firefox) {
      await browser.send("browsingContext.navigate", {
        context,
        url: endpoint.href,
        wait: "complete",
      });
      const result = await browser.send("script.evaluate", {
        expression: "document.body.textContent",
        target: { context },
        awaitPromise: true,
      });
      assert.equal(result.type, "success");
      response = parseEndpointJSON(result.result.value);
    } else {
      const navigation = await browser.send(
        "Page.navigate",
        { url: endpoint.href },
        sessionId,
      );
      assert(!navigation.errorText, navigation.errorText);
      for (let i = 0; i < 100; i++) {
        try {
          const evaluation = await browser.send(
            "Runtime.evaluate",
            {
              expression: `location.href === ${JSON.stringify(endpoint.href)} && document.readyState === 'complete' ? document.body.textContent : null`,
              returnByValue: true,
            },
            sessionId,
          );
          const value = evaluation.result?.value;
          if (typeof value === "string") {
            response = parseEndpointJSON(value.slice(value.indexOf("{")));
            break;
          }
        } catch (error) {
          if (i === 99) throw error;
        }
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    assert(response, "navigation produced no JSON response");
    attempts.push({
      attempt: n + 1,
      protocol: response.protocol || response.http_version || null,
      error: response.error || null,
    });
    if (response.protocol === "http3") break;
    // Allow ordinary Alt-Svc discovery to finish; this is an endpoint snapshot,
    // not an experiment about connection racing or application timing.
    await new Promise((r) => setTimeout(r, 500));
  }
  assert.equal(
    response?.protocol,
    "http3",
    "normal browser did not select HTTP/3; no protocol override will be applied",
  );
  writeFileSync(
    join(directory, "browser-endpoint.json"),
    JSON.stringify(response, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.log(
    JSON.stringify({ browser: args.browser, complete: true, attempts }),
  );
} finally {
  await browser.close(firefox ? "browser.close" : "Browser.close");
  writeFileSync(join(directory, "browser.log"), browser.logs(), {
    mode: 0o600,
  });
  writeFileSync(
    join(directory, "browser.json"),
    JSON.stringify(
      {
        metadata,
        flags,
        prefs,
        attempts,
        endpoint: endpoint.href,
        captured_at: new Date().toISOString(),
        method:
          "Fresh ordinary browser, public TLS verification, standard Alt-Svc discovery. Only isolated profile and automation/UI controls; no protocol, certificate, resolver, proxy or User-Agent overrides.",
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
}
