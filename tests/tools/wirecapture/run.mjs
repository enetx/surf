import { spawn, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  writeFileSync,
  copyFileSync,
  readFileSync,
} from "node:fs";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")),
);
const root = resolve(
  args.out || mkdtempSync(join(tmpdir(), "surf-browser-wire-")),
);
const binary = args.binary || "/tmp/surf-wirecapture";
const browsers = (args.browser || "chrome,firefox").split(",");
const protocols = (args.protocol || "h2,h3").split(",");
const capacities = (args.capacity || "0,128,4096,65536").split(",").map(Number);
mkdirSync(root, { recursive: true, mode: 0o700 });
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function launch(executable, flags, pattern) {
  const proc = spawn(executable, flags, { stdio: ["ignore", "pipe", "pipe"] });
  let logs = "";
  const exited = new Promise((r) => proc.once("exit", r));
  const address = await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(Error("browser startup: " + logs.slice(-1500))),
      30000,
    );
    function consume(chunk) {
      logs += chunk.toString();
      const m = logs.match(pattern);
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    }
    proc.stdout.on("data", consume);
    proc.stderr.on("data", consume);
    proc.once("error", reject);
    proc.once("exit", (code) => {
      clearTimeout(timer);
      reject(Error("browser exited " + code + ": " + logs.slice(-1000)));
    });
  });
  const ws = new WebSocket(
    address + (executable.includes("Firefox") ? "/session" : ""),
  );
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });
  let next = 0;
  const pending = new Map();
  ws.addEventListener("message", (event) => {
    const data = JSON.parse(event.data);
    const p = pending.get(data.id);
    if (!p) return;
    pending.delete(data.id);
    clearTimeout(p.timer);
    if (data.type === "error" || data.error)
      p.reject(Error(JSON.stringify(data)));
    else p.resolve(data.result);
  });
  function send(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++next;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(Error(method + " timeout"));
      }, 20000);
      pending.set(id, { resolve, reject, timer });
      ws.send(
        JSON.stringify({
          id,
          method,
          params,
          ...(sessionId ? { sessionId } : {}),
        }),
      );
    });
  }
  async function close(method) {
    try {
      await send(method);
    } catch {}
    if (ws.readyState === WebSocket.OPEN) ws.close();
    for (const p of pending.values()) {
      clearTimeout(p.timer);
      p.reject(Error("browser closed"));
    }
    proc.kill("SIGTERM");
    await Promise.race([exited, delay(3000)]);
    if (proc.exitCode === null) proc.kill("SIGKILL");
  }
  return { send, close, logs: () => logs };
}

async function browserRun(browser, server, directory, protocol) {
  const profile = mkdtempSync(join(directory, "profile-"));
  let flags,
    prefs = {},
    automation,
    metadata;
  if (browser === "chrome") {
    flags = [
      "--headless",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--no-proxy-server",
      "--remote-debugging-port=0",
      "--user-data-dir=" + profile,
      "--ignore-certificate-errors-spki-list=" + server.spki,
    ];
    flags.push(
      ...(protocol === "h3"
        ? [
            "--enable-quic",
            "--origin-to-force-quic-on=127.0.0.1:" + server.port,
          ]
        : ["--disable-quic"]),
    );
    flags.push("about:blank");
    automation = await launch(
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
      flags,
      /DevTools listening on (ws:\/\/[^\s]+)/,
    );
    try {
      metadata = await automation.send("Browser.getVersion");
      const { targetId } = await automation.send("Target.createTarget", {
        url: "about:blank",
      });
      const { sessionId } = await automation.send("Target.attachToTarget", {
        targetId,
        flatten: true,
      });
      await automation.send("Page.enable", {}, sessionId);
      const navigation = await automation.send(
        "Page.navigate",
        { url: server.origin + "/scenario" },
        sessionId,
      );
      if (navigation.errorText) throw Error(navigation.errorText);
      await waitComplete(server);
    } finally {
      await automation.close("Browser.close");
      writeFileSync(join(directory, "browser.log"), automation.logs());
    }
  } else {
    const certutil = "/opt/homebrew/opt/nss/bin/certutil";
    for (const command of [
      ["-N", "-d", "sql:" + profile, "--empty-password"],
      [
        "-A",
        "-d",
        "sql:" + profile,
        "-n",
        "Surf wire capture localhost",
        "-t",
        "C,,",
        "-i",
        server.certificate,
      ],
    ]) {
      const result = spawnSync(certutil, command, { encoding: "utf8" });
      if (result.status !== 0) throw Error("certutil: " + result.stderr);
    }
    prefs = {
      "remote.prefs.recommended": false,
      "devtools.jsonview.enabled": false,
      "browser.shell.checkDefaultBrowser": false,
      "browser.startup.homepage_override.mstone": "ignore",
      "browser.startup.page": 0,
      "network.proxy.type": 0,
      "network.http.http3.enable": protocol === "h3",
    };
    // The testing map is keyed by GetAsciiHost(), without the origin port.
    // https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp
    // The imported root belongs only to this disposable NSS profile.
    if (protocol === "h3")
      Object.assign(prefs, {
        "network.http.http3.alt-svc-mapping-for-testing": `127.0.0.1;h3=":${server.port}"`,
        "network.http.http3.force-use-alt-svc-mapping-for-testing": true,
        "network.http.http3.disable_when_third_party_roots_found": false,
      });
    writeFileSync(
      join(profile, "user.js"),
      Object.entries(prefs)
        .map(
          ([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`,
        )
        .join("\n") + "\n",
    );
    flags = [
      "--headless",
      "--no-remote",
      "--profile",
      profile,
      "--remote-debugging-port=0",
      "about:blank",
    ];
    automation = await launch(
      "/Applications/Firefox.app/Contents/MacOS/firefox",
      flags,
      /WebDriver BiDi listening on (ws:\/\/127\.0\.0\.1:\d+)/,
    );
    try {
      metadata = await automation.send("session.new", {
        capabilities: { alwaysMatch: { acceptInsecureCerts: false } },
      });
      const tree = await automation.send("browsingContext.getTree");
      const context = tree.contexts[0].context;
      await automation.send("browsingContext.navigate", {
        context,
        url: server.origin + "/scenario",
        wait: "complete",
      });
      await waitComplete(server);
    } finally {
      await automation.close("browser.close");
      writeFileSync(join(directory, "browser.log"), automation.logs());
    }
  }
  writeFileSync(join(directory, "browser.log"), automation.logs());
  writeFileSync(
    join(directory, "browser.json"),
    JSON.stringify(
      {
        browser,
        flags,
        prefs,
        metadata,
        captured_at: new Date().toISOString(),
      },
      null,
      2,
    ) + "\n",
  );
}

async function waitComplete(server) {
  for (let n = 0; n < 200; n++) {
    const status = await (await fetch(server.admin + "/status")).json();
    if (status.failure) throw Error(status.failure);
    if (status.complete) {
      await delay(200);
      return;
    }
    await delay(100);
  }
  throw Error(
    "scenario timeout: " +
      JSON.stringify(await (await fetch(server.admin + "/status")).json()),
  );
}

async function captureCase(browser, protocol, capacity) {
  const directory = join(root, `${browser}-${protocol}-${capacity}`);
  // Refuse to overwrite a prior capture or mix it with a new browser run.
  mkdirSync(directory, { mode: 0o700 });
  const proc = spawn(
    binary,
    ["-out", directory, "-protocol", protocol, "-capacity", String(capacity)],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let logs = "";
  proc.stderr.on("data", (b) => (logs += b));
  const exited = new Promise((r) => proc.once("exit", r));
  const server = await new Promise((resolve, reject) => {
    let text = "";
    const timer = setTimeout(
      () => reject(Error("server startup " + logs)),
      15000,
    );
    proc.stdout.on("data", (b) => {
      text += b;
      try {
        const ready = JSON.parse(text.trim());
        clearTimeout(timer);
        resolve(ready);
      } catch {}
    });
    proc.once("exit", (c) => {
      clearTimeout(timer);
      reject(Error("server exited " + c + ": " + logs));
    });
  });
  writeFileSync(
    join(directory, "server.json"),
    JSON.stringify(server, null, 2) + "\n",
  );
  try {
    await browserRun(browser, server, directory, protocol);
    copyFileSync(
      join(directory, "requests.jsonl"),
      join(directory, "browser-requests.jsonl"),
    );
    const captured = readFileSync(
      join(directory, "browser-requests.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n")
      .map(JSON.parse);
    if (captured.length !== 11 || captured.some((r) => r.protocol !== protocol))
      throw Error(
        "browser protocol/count mismatch: " +
          JSON.stringify(captured.map((r) => [r.protocol, r.path])),
      );
    for (const stock of [true, false]) {
      const label = stock ? "surf-preset" : "surf-exact-input";
      await fetch(server.admin + "/label?value=" + label);
      const result = spawnSync(
        binary,
        [
          "-replay",
          join(directory, "browser-requests.jsonl"),
          "-origin",
          server.origin,
          "-browser",
          browser,
          "-protocol",
          protocol,
          ...(stock ? ["-stock"] : []),
        ],
        { encoding: "utf8", timeout: 40000 },
      );
      writeFileSync(
        join(directory, label + ".log"),
        result.stdout + result.stderr,
      );
      if (result.status !== 0) throw Error(label + ": " + result.stderr);
    }
  } finally {
    await fetch(server.admin + "/finish").catch(() => {});
    await Promise.race([exited, delay(3000)]);
    proc.kill("SIGTERM");
    writeFileSync(join(directory, "server.log"), logs);
  }
  const result = spawnSync(
    "tshark",
    [
      "-2",
      "-r",
      join(directory, "wire.pcap"),
      "-o",
      "tls.keylog_file:" + join(directory, "tls.keys"),
      "-d",
      `tcp.port==${server.port},tls`,
      "--no-duplicate-keys",
      "-T",
      "json",
    ],
    { encoding: "utf8", maxBuffer: 64 << 20 },
  );
  if (result.status !== 0) throw Error("tshark: " + result.stderr);
  writeFileSync(join(directory, "wireshark.json"), result.stdout);
  writeFileSync(join(directory, "wireshark.log"), result.stderr);
  const digest = createHash("sha256")
    .update(readFileSync(join(directory, "wire.pcap")))
    .digest("hex");
  console.log(
    JSON.stringify({
      browser,
      protocol,
      capacity,
      directory,
      pcap_sha256: digest,
    }),
  );
}

for (const browser of browsers)
  for (const protocol of protocols)
    for (const capacity of protocol === "h2" ? [4096] : capacities)
      await captureCase(browser, protocol, capacity);
console.log(JSON.stringify({ complete: true, directory: root }));
