import assert from "node:assert/strict";
import test from "node:test";
import { Readable } from "node:stream";
import { jsonObjects } from "./json-stream.mjs";

const read = async (chunks, limit) =>
  Array.fromAsync(jsonObjects(Readable.from(chunks), limit));

test("packet JSON survives every chunk boundary and escaped delimiters", async () => {
  const packets = [{ text: '}[\\\"],☃', nested: [{ x: 2 }] }, { next: true }];
  const text = JSON.stringify(packets);
  for (let i = 1; i < text.length; i++) {
    assert.deepEqual(await read([text.slice(0, i), text.slice(i)]), packets);
  }
  assert.deepEqual(await read([...text]), packets);
  assert.deepEqual(await read(["  [ ]\n"]), []);
});

test("malformed, truncated and oversized capture JSON cannot become evidence", async () => {
  for (const text of [
    "",
    "[",
    "[{}",
    "[{]",
    "[{},]",
    "[{}]{}",
    "[true]",
    "{}",
    '[{"a":"unfinished}',
  ]) {
    await assert.rejects(read([text]));
  }
  await assert.rejects(read(['[{"a":"123456789"}]'], 8), /exceeds limit/);
  await assert.rejects(
    read(["[{", '"a":"123456789"', "}]"], 8),
    /exceeds limit/,
  );
  assert.deepEqual(await read(["[{},{}]"], 2), [{}, {}]);
});
