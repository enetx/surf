import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createRequire } from "node:module";
if (!globalThis.WebSocket)
  globalThis.WebSocket = createRequire(import.meta.url)("ws");
const { launchBrowser } = await import("../wirecapture/browser.mjs");
const [kind, directory, executable, protocol = "h3", action = "navigation"] =
  process.argv.slice(2);
assert(["chrome", "firefox"].includes(kind));
assert(
  directory && executable,
  "usage: native.mjs chrome|firefox NEW_PRIVATE_DIR BROWSER_PATH [h2|h3] [navigation|fetch|no-cors-fetch]",
);
assert(
  ["h2", "h3"].includes(protocol) &&
    ["navigation", "fetch", "no-cors-fetch"].includes(action),
);
const captureURL = process.env.SURF_CAPTURE_URL
  ? new URL(process.env.SURF_CAPTURE_URL)
  : null;
assert(
  !captureURL ||
    (captureURL.protocol === "https:" && action === "no-cors-fetch"),
  "SURF_CAPTURE_URL requires an HTTPS endpoint and no-cors-fetch",
);
const dnsMode = process.env.SURF_CAPTURE_DNS ?? "cloudflare";
assert(["cloudflare", "default"].includes(dnsMode), "unsupported capture DNS mode");

const out = resolve(directory);
mkdirSync(out, { mode: 0o700 });
mkdirSync(out + "/profile", { mode: 0o700 });
process.env.SSLKEYLOGFILE = out + "/keys.log";
writeFileSync(process.env.SSLKEYLOGFILE, "", { mode: 0o600, flag: "wx" });
const firefox = kind === "firefox";
const prefs = firefox
  ? {
      "remote.prefs.recommended": false,
      "devtools.jsonview.enabled": false,
      "browser.shell.checkDefaultBrowser": false,
      "browser.startup.page": 0,
      ...(dnsMode === "cloudflare"
        ? {
            "network.trr.mode": 3,
            "network.trr.uri": "https://cloudflare-dns.com/dns-query",
            "network.trr.bootstrapAddress": "1.1.1.1",
          }
        : {}),
      ...(process.env.SURF_CAPTURE_QLOG === "1"
        ? { "network.http.http3.enable_qlog": true }
        : {}),
    }
  : dnsMode === "default"
    ? {}
    : {
        dns_over_https: {
          mode: "secure",
          templates: "https://cloudflare-dns.com/dns-query",
        },
      };
writeFileSync(
  out + "/profile/" + (firefox ? "user.js" : "Local State"),
  firefox
    ? Object.entries(prefs)
        .map(
          ([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`,
        )
        .join("\n") + "\n"
    : JSON.stringify(prefs),
  { mode: 0o600 },
);
const flags = firefox
  ? [
      "--no-remote",
      "--profile",
      out + "/profile",
      "--remote-debugging-port=0",
      "about:blank",
    ]
  : [
      "--user-data-dir=" + out + "/profile",
      "--remote-debugging-port=0",
      "--no-first-run",
      "--log-net-log=" + out + "/netlog.json",
      "--net-log-capture-mode=Everything",
      "about:blank",
    ];
const b = await launchBrowser(
  executable,
  flags,
  firefox
    ? /WebDriver BiDi listening on (ws:\/\/127\.0\.0\.1:\d+)/
    : /DevTools listening on (ws:\/\/[^\s]+)/,
);
const method =
  protocol === "h3"
    ? "Natural QUIC idle expiry before ordinary " + action
    : firefox
      ? "Normal location.reload(true)"
      : "Built-in socket-pool flush (TLS session cache retained)";
const report = {
  kind,
  dnsMode,
  prefs,
  flags,
  attempts: [],
  started_at: new Date().toISOString(),
  method:
    method +
    "; certificate verification enabled; no protocol or certificate overrides.",
};
if (captureURL) report.endpoint = captureURL.origin + captureURL.pathname;
if (action === "no-cors-fetch")
  report.method +=
    " Cross-origin opaque fetches retain one about:blank document; protocol and ECH require transcript verification, not response-body inference.";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let context, sessionId, currentURL;
async function navigate(url) {
  if (firefox) {
    await b.send("browsingContext.navigate", {
      context,
      url,
      wait: "complete",
    });
  } else {
    const r = await b.send("Page.navigate", { url }, sessionId);
    assert(!r.errorText, r.errorText);
  }
}
async function trace(phase, reload = false) {
  const host =
    protocol === "h2" ? "crypto.cloudflare.com" : "www.cloudflare-quic.com";
  let url = reload
    ? currentURL
    : "https://" +
      host +
      "/cdn-cgi/trace?surf-resumption=" +
      report.attempts.length;
  if (captureURL) {
    const target = new URL(captureURL);
    target.searchParams.set("surf-resumption", report.attempts.length);
    url = target.href;
  }

  if (action === "no-cors-fetch") {
    // A JSON string has the same primitive representation in CDP and BiDi;
    // BiDi's remote object values are not ordinary JavaScript dictionaries.
    const expression = `fetch(${JSON.stringify(url)}, {mode: 'no-cors', credentials: 'omit'}).then(response => JSON.stringify({type: response.type, status: response.status}))`;
    const result = firefox
      ? await b.send("script.evaluate", {
          expression,
          target: { context },
          awaitPromise: true,
        })
      : await b.send(
          "Runtime.evaluate",
          { expression, returnByValue: true, awaitPromise: true },
          sessionId,
        );

    assert(
      !result.exceptionDetails && (!firefox || result.type === "success"),
      "ordinary opaque fetch failed",
    );

    const fields = JSON.parse(result.result?.value);
    assert.equal(fields.type, "opaque");
    report.attempts.push({ phase, at: new Date().toISOString(), ...fields });
    console.log(JSON.stringify(report.attempts.at(-1)));
    return fields;
  }
  let previousOrigin = 0;
  let fetchBody;
  if (action === "fetch" && phase === "after-idle") {
    const expression = `fetch(${JSON.stringify(url)}).then(response => response.text())`;
    const r = firefox
      ? await b.send("script.evaluate", {
          expression,
          target: { context },
          awaitPromise: true,
        })
      : await b.send(
          "Runtime.evaluate",
          { expression, returnByValue: true, awaitPromise: true },
          sessionId,
        );
    fetchBody = r.result?.value;
  } else if (reload) {
    previousOrigin = (
      await b.send("script.evaluate", {
        expression: "performance.timeOrigin",
        target: { context },
        awaitPromise: true,
      })
    ).result.value;
    await b.send("script.evaluate", {
      expression: "setTimeout(() => location.reload(true), 0); null",
      target: { context },
      awaitPromise: false,
    });
  } else await navigate(url);
  currentURL = url;
  let body = fetchBody;
  for (let n = 0; n < 120; n++) {
    if (typeof body === "string" && body.includes("visit_scheme=https")) break;
    const expression = `location.href === ${JSON.stringify(url)} && performance.timeOrigin > ${previousOrigin} && document.readyState === 'complete' ? document.body.textContent : null`;
    const r = firefox
      ? await b.send("script.evaluate", {
          expression,
          target: { context },
          awaitPromise: true,
        })
      : await b.send(
          "Runtime.evaluate",
          { expression, returnByValue: true },
          sessionId,
        );
    body = firefox ? r.result?.value : r.result?.value;
    if (typeof body === "string" && body.includes("visit_scheme=https")) break;
    await sleep(200);
  }
  assert.equal(typeof body, "string");
  const fields = Object.fromEntries(
    body
      .split("\n")
      .filter((x) => /^(http|sni|tls|kex)=/.test(x))
      .map((x) => x.split("=")),
  );
  report.attempts.push({ phase, at: new Date().toISOString(), ...fields });
  console.log(JSON.stringify(report.attempts.at(-1)));
  return fields;
}
try {
  if (firefox) {
    report.browser = await b.send("session.new", {
      capabilities: { alwaysMatch: { acceptInsecureCerts: false } },
    });
    context = (await b.send("browsingContext.getTree")).contexts[0].context;
  } else {
    report.browser = await b.send("Browser.getVersion");
    const { targetId } = await b.send("Target.createTarget", {
      url: "about:blank",
    });
    ({ sessionId } = await b.send("Target.attachToTarget", {
      targetId,
      flatten: true,
    }));
    await b.send("Page.enable", {}, sessionId);
  }
  let fields;
  const warmups = action === "no-cors-fetch" ? (firefox ? 4 : 2) : 6;
  for (let n = 0; n < warmups; n++) {
    fields = await trace("warm");
    if (
      action !== "no-cors-fetch" &&
      fields.http === (protocol === "h2" ? "http/2" : "http/3")
    )
      break;
    await sleep(2000);
  }
  if (action !== "no-cors-fetch")
    assert.equal(
      fields.http,
      protocol === "h2" ? "http/2" : "http/3",
      "ordinary browser selected an unexpected protocol",
    );
  if (protocol === "h2") {
    let controlSession;
    if (!firefox) {
      const { targetId } = await b.send("Target.createTarget", {
        url: "chrome://net-internals/#sockets",
      });
      ({ sessionId: controlSession } = await b.send("Target.attachToTarget", {
        targetId,
        flatten: true,
      }));
      await sleep(1000);
    }
    for (let n = 0; n < 2; n++) {
      await sleep(1500);
      if (!firefox) {
        const result = await b.send(
          "Runtime.evaluate",
          {
            expression: "chrome.send('flushSocketPools'); 'flushed'",
            returnByValue: true,
          },
          controlSession,
        );
        assert(!result.exceptionDetails, "socket-pool UI action failed");
        await sleep(300);
      }
      await trace(firefox ? "hard-reload" : "socket-pool-flush", firefox);
    }
  } else {
    const repeats = firefox && action === "no-cors-fetch" ? 3 : 2;
    for (let n = 0; n < repeats; n++) {
      if (action === "navigation") await navigate("about:blank");
      console.log(JSON.stringify({ phase: "idle", milliseconds: 45000 }));
      await sleep(45000);
      await trace("after-idle");
    }
  }
} finally {
  report.completed_at = new Date().toISOString();
  writeFileSync(out + "/report.json", JSON.stringify(report, null, 2), {
    mode: 0o600,
  });
  await b.close(firefox ? "browser.close" : "Browser.close");
  writeFileSync(out + "/browser.log", b.logs(), { mode: 0o600 });
}
