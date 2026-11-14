import assert from "node:assert/strict";
import { createReadStream, createWriteStream, writeFileSync } from "node:fs";
import { once } from "node:events";
import { jsonObjects } from "./json-stream.mjs";
import { bulkPackets } from "./bulk-packets.mjs";

const [input, prefix, authority] = process.argv.slice(2);
assert(
  input && prefix && authority,
  "usage: bulk-reduce.mjs tshark.json output-prefix authority",
);
const output = createWriteStream(prefix + "-packets.jsonl", {
  mode: 0o600,
  flags: "wx",
});
const requests = [],
  unattributed = [],
  fields = {},
  connections = new Set();
let count = 0;
for await (const row of jsonObjects(createReadStream(input))) {
  const decoded = bulkPackets(row, authority);
  unattributed.push(...decoded.unattributed);
  for (const packet of decoded.packets) {
    if (!output.write(JSON.stringify(packet) + "\n"))
      await once(output, "drain");
    count++;
  }
  for (const request of decoded.requests) {
    assert(
      !fields[request.id] ||
        JSON.stringify(fields[request.id]) === JSON.stringify(request.fields),
      "conflicting request fields",
    );
    fields[request.id] = request.fields;
    requests.push(request);
    connections.add(request.connection);
  }
}
output.end();
await once(output, "finish");
writeFileSync(
  prefix + "-headers.json",
  JSON.stringify(fields, null, 2) + "\n",
  { mode: 0o600, flag: "wx" },
);
writeFileSync(
  prefix + "-requests.json",
  JSON.stringify(
    { connections: [...connections], requests, packets: count, unattributed },
    null,
    2,
  ) + "\n",
  { mode: 0o600, flag: "wx" },
);
console.log(
  JSON.stringify({
    packets: count,
    connections: [...connections],
    cases: Object.keys(fields),
  }),
);
