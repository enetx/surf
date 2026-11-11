// Build an analysis pcap from native UDP payloads. The envelopes are synthetic:
// this establishes QUIC/TLS bytes, not NIC timing or IP/UDP header parity.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function udpCapture(log, source) {
  const types = new Map(
    Object.entries(log.constants.logEventTypes).map(([k, v]) => [v, k]),
  );
  const session = log.events.find(
    (e) => e.source.id === source && types.get(e.type) === "QUIC_SESSION",
  );
  const id = session?.params.connection_id?.replaceAll(":", "").toLowerCase();
  assert(
    id && /^(?:[0-9a-f]{2})+$/.test(id),
    "missing QUIC session connection ID",
  );
  const sockets = new Set();
  for (const event of log.events) {
    if (types.get(event.type) !== "UDP_BYTES_SENT" || !event.params?.bytes)
      continue;
    const p = Buffer.from(event.params.bytes, "base64");
    if (
      p.length >= 6 &&
      (p[0] & 0xc0) === 0xc0 &&
      p.subarray(6, 6 + p[5]).toString("hex") === id
    )
      sockets.add(event.source.id);
  }
  assert(
    sockets.size === 1,
    "QUIC DCID does not identify exactly one UDP socket",
  );
  const socket = [...sockets][0];
  const events = log.events.filter(
    (e) =>
      e.source.id === socket &&
      ["UDP_BYTES_SENT", "UDP_BYTES_RECEIVED"].includes(types.get(e.type)),
  );
  assert(events.length > 0, "no captured UDP payloads");
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(101, 20);
  const records = [header],
    origin = Number(events[0].time);
  for (const event of events) {
    const p = event.params,
      payload = Buffer.from(p.bytes ?? "", "base64");
    assert(
      payload.length === p.byte_count && payload.length <= 65507,
      "missing/truncated UDP payload (use Everything NetLog)",
    );
    const sent = types.get(event.type) === "UDP_BYTES_SENT";
    const packet = Buffer.alloc(28 + payload.length);
    packet[0] = 0x45;
    packet.writeUInt16BE(packet.length, 2);
    packet[8] = 64;
    packet[9] = 17;
    Buffer.from(
      sent
        ? [198, 51, 100, 1, 198, 51, 100, 2]
        : [198, 51, 100, 2, 198, 51, 100, 1],
    ).copy(packet, 12);
    let sum = 0;
    for (let i = 0; i < 20; i += 2) sum += packet.readUInt16BE(i);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    packet.writeUInt16BE(~sum & 65535, 10);
    packet.writeUInt16BE(sent ? 45000 : 443, 20);
    packet.writeUInt16BE(sent ? 443 : 45000, 22);
    packet.writeUInt16BE(payload.length + 8, 24);
    payload.copy(packet, 28);
    const micros = Math.round((Number(event.time) - origin) * 1000);
    assert(
      Number.isSafeInteger(micros) && micros >= 0,
      "invalid NetLog timestamps",
    );
    const record = Buffer.alloc(16);
    record.writeUInt32LE(Math.floor(micros / 1e6));
    record.writeUInt32LE(micros % 1e6, 4);
    record.writeUInt32LE(packet.length, 8);
    record.writeUInt32LE(packet.length, 12);
    records.push(record, packet);
  }
  return { data: Buffer.concat(records), socket, packets: events.length };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const [input, source, output] = process.argv.slice(2);
  assert(
    input && source && output,
    "usage: netlog.mjs PRIVATE_NETLOG SOURCE NEW_ANALYSIS_PCAP",
  );
  const result = udpCapture(
    JSON.parse(readFileSync(input, "utf8")),
    Number(source),
  );
  writeFileSync(output, result.data, { mode: 0o600, flag: "wx" });
  console.log(
    JSON.stringify({
      udp_socket: result.socket,
      datagrams: result.packets,
      synthetic_envelopes: true,
    }),
  );
}
