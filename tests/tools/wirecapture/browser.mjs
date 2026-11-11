import { spawn } from "node:child_process";
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export async function launchBrowser(executable, flags, pattern) {
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
    address + (pattern.source.includes("WebDriver BiDi") ? "/session" : ""),
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
      const timer = setTimeout(
        () => {
          pending.delete(id);
          reject(Error(method + " timeout"));
        },
        method === "session.new" ? 60000 : 20000,
      );
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
