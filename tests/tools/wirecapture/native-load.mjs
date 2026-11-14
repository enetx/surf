import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { launchBrowser } from "./browser.mjs";
const [kind, out, executable, planPath] = process.argv.slice(2);
assert(
  ["chrome", "firefox"].includes(kind) && out && executable && planPath,
  "usage: native-load.mjs chrome|firefox new-output executable plan.json",
);
const plan = JSON.parse(readFileSync(planPath, "utf8"));
assert(
  new URL(plan.origin).protocol === "https:" && plan.steps.length,
  "HTTPS bulk plan required",
);
mkdirSync(out, { mode: 0o700 });
mkdirSync(out + "/profile", { mode: 0o700 });
process.env.SSLKEYLOGFILE = out + "/keys.log";
writeFileSync(process.env.SSLKEYLOGFILE, "", { mode: 0o600, flag: "wx" });
const ff = kind === "firefox";
const prefs = ff
  ? {
      "remote.prefs.recommended": false,
      "browser.shell.checkDefaultBrowser": false,
      "browser.startup.page": 0,
    }
  : {};
if (ff)
  writeFileSync(
    out + "/profile/user.js",
    Object.entries(prefs)
      .map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`)
      .join("\n") + "\n",
  );
const flags = ff
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
      "about:blank",
    ];
const b = await launchBrowser(
  executable,
  flags,
  ff
    ? /WebDriver BiDi listening on (ws:\/\/127\.0\.0\.1:\d+)/
    : /DevTools listening on (ws:\/\/[^\s]+)/,
  { commandTimeout: 180000 },
);
const report = {
  schema: 1,
  kind,
  flags,
  prefs,
  plan,
  condition: process.env.SURF_LOAD_CONDITION ?? "baseline",
  attempts: [],
  started_at: new Date().toISOString(),
};
let context, sessionId;
async function evaluate(expression) {
  const r = ff
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
    !r.exceptionDetails && (!ff || r.type === "success"),
    JSON.stringify(r),
  );
  return JSON.parse(r.result.value);
}
async function run(step) {
  const target = new URL(step.path, plan.origin);
  target.searchParams.set("case", step.id);
  const expression = `(async()=>{
  const step=${JSON.stringify(step)},url=${JSON.stringify(target.href)},start=performance.now();
  const hex=bytes=>Array.from(new Uint8Array(bytes),byte=>byte.toString(16).padStart(2,'0')).join('');
  const options={method:step.method,credentials:'omit'};if(step.range)options.headers={Range:step.range};
  let input;
  if(step.method==='POST'){
   input=new Uint8Array(step.size).fill(90);
   if(step.streaming){
    let offset=0,duplexRead=false;
    options.body=new ReadableStream({pull(controller){if(offset===input.length){controller.close();return}const end=Math.min(offset+16384,input.length);controller.enqueue(input.subarray(offset,end));offset=end;}});
    Object.defineProperty(options,'duplex',{enumerable:true,get(){duplexRead=true;return 'half'}});
    const probe=new Request(url,options);
    if(!duplexRead||probe.headers.has('Content-Type'))return JSON.stringify({id:step.id,url,unsupported:'streaming fetch request body',duplexRead});
   }else options.body=input;
  }
  try{
   const response=await fetch(url,options);
   const bytes=await response.arrayBuffer(),finished=performance.now();
   const timing=performance.getEntriesByName(url).at(-1);
   const result={id:step.id,url,method:step.method,status:response.status,protocol:timing?.nextHopProtocol??null,bytes:bytes.byteLength,duration_ms:finished-start,encoded_body_bytes:timing?.encodedBodySize??null,content_encoding:response.headers.get('content-encoding')};
   if(step.method==='POST'){
    result.upload=step.echo?{bytes:bytes.byteLength,sha256:hex(await crypto.subtle.digest('SHA-256',bytes))}:JSON.parse(new TextDecoder().decode(bytes));
    result.expected_sha256=hex(await crypto.subtle.digest('SHA-256',input));
    result.valid=result.upload.bytes===step.size&&result.upload.sha256===result.expected_sha256&&(step.echo||result.upload.error==='<nil>');
   }else{
    result.sha256=hex(await crypto.subtle.digest('SHA-256',bytes));
    result.expected_sha256=step.sha256??response.headers.get('x-body-sha256');
    result.valid=bytes.byteLength===step.size&&result.sha256===result.expected_sha256;
   }
   return JSON.stringify(result);
  }catch(error){return JSON.stringify({id:step.id,url,error:String(error),duration_ms:performance.now()-start})}
 })()`;
  const result = await evaluate(expression);
  report.attempts.push(result);
  console.log(JSON.stringify(result));
  writeFileSync(out + "/report.json", JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
  return result;
}
try {
  if (ff) {
    report.browser = await b.send("session.new", {
      capabilities: { alwaysMatch: { acceptInsecureCerts: false } },
    });
    context = (await b.send("browsingContext.getTree")).contexts[0].context;
    await b.send("browsingContext.navigate", {
      context,
      url: plan.origin + (plan.navigation ?? "/ready"),
      wait: "complete",
    });
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
    const navigation = await b.send(
      "Page.navigate",
      { url: plan.origin + (plan.navigation ?? "/ready") },
      sessionId,
    );
    assert(!navigation.errorText, navigation.errorText);
    for (let i = 0; i < 100; i++) {
      const state = await evaluate(
        `JSON.stringify({ready:location.origin===${JSON.stringify(plan.origin)}&&document.readyState==='complete'})`,
      );
      if (state.ready) break;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  report.identity = await evaluate(
    `JSON.stringify({userAgent:navigator.userAgent,platform:navigator.platform})`,
  );
  let ready = false;
  for (let i = 0; i < 8; i++) {
    const r = await run({
      ...(plan.warmup ?? { method: "GET", path: "/get/1024", size: 1024 }),
      id: "warm-" + i,
    });
    if (
      r.protocol === "h3" &&
      r.status === (plan.warmup?.status ?? 200) &&
      r.valid
    ) {
      ready = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  assert(ready, "ordinary browser never selected valid HTTP/3");
  for (const step of plan.steps) await run(step);
  if (!ff) {
    report.histograms = {};
    for (const name of [
      "Net.QuicSession.ReadMultipleNumPackets",
      "Net.UDPSocketPosix.RecvMmsgPacketsRead",
      "Net.UDPSocketPosix.GroPacketsRead",
    ]) {
      try {
        report.histograms[name] = await b.send("Browser.getHistogram", {
          name,
        });
      } catch (error) {
        report.histograms[name] = { error: String(error) };
      }
    }
  }
  report.complete = report.attempts
    .filter((r) => !r.id.startsWith("warm-"))
    .every(
      (r) =>
        r.status ===
          (plan.steps.find((step) => step.id === r.id)?.status ?? 200) &&
        r.protocol === "h3" &&
        r.valid,
    );
} finally {
  await b.close(ff ? "browser.close" : "Browser.close");
  report.finished_at = new Date().toISOString();
  writeFileSync(out + "/browser.log", b.logs(), { mode: 0o600 });
  writeFileSync(out + "/report.json", JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
}
assert(report.complete, "one or more bulk cases failed");
