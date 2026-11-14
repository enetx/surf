import assert from "node:assert/strict";

// TShark can repeat a reassembled body in a single packet object. Bound each
// object and stream the outer array rather than retaining the entire capture.
export async function* jsonObjects(stream, limit = 512 * 1024 * 1024) {
  assert(Number.isSafeInteger(limit) && limit > 0, "invalid JSON object limit");
  stream.setEncoding?.("utf8");
  let state = "start",
    depth = 0,
    string = false,
    escaped = false;
  let parts = [],
    length = 0,
    empty = true;
  for await (const chunk of stream) {
    const text = String(chunk);
    let begin = state === "object" ? 0 : null;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (state === "object") {
        if (string) {
          if (escaped) escaped = false;
          else if (c === "\\") escaped = true;
          else if (c === '"') string = false;
        } else if (c === '"') string = true;
        else if (c === "{" || c === "[") depth++;
        else if (c === "}" || c === "]") depth--;
        if (depth === 0) {
          parts.push(text.slice(begin, i + 1));
          length += i + 1 - begin;
          assert(length <= limit, "JSON packet exceeds limit");
          const object = JSON.parse(parts.join(""));
          parts = [];
          length = 0;
          begin = null;
          state = "after";
          yield object;
        }
        continue;
      }
      if (/\s/.test(c)) continue;
      if (state === "start") {
        assert(c === "[", "expected JSON array");
        state = "before";
        continue;
      }
      if (state === "before") {
        if (c === "]" && empty) {
          state = "end";
          continue;
        }
        assert(c === "{", "expected packet object");
        state = "object";
        depth = 1;
        string = false;
        escaped = false;
        begin = i;
        empty = false;
        continue;
      }
      if (state === "after") {
        if (c === ",") {
          state = "before";
          continue;
        }
        assert(c === "]", "expected array separator");
        state = "end";
        continue;
      }
      assert.fail("data after JSON array");
    }
    if (state === "object") {
      const tail = text.slice(begin);
      parts.push(tail);
      length += tail.length;
      assert(length <= limit, "JSON packet exceeds limit");
    }
  }
  assert(state === "end", "truncated JSON array");
}
