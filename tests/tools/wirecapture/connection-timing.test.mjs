import assert from "node:assert/strict";
import test from "node:test";
import { connectionTiming } from "./connection-timing.mjs";

test("HTTP/3-only browser does not inherit a later Surf TCP handshake", () => {
  const initial = [1.1, 1.2, 3.1],
    hello = [3.201];
  assert.equal(
    connectionTiming(initial, hello, { start: 1, end: 2 })
      .tcp_clienthello_after_udp_initial_ms,
    null,
  );
  assert.deepEqual(connectionTiming(initial, hello, { start: 3, end: 4 }), {
    initial_datagrams: 1,
    tcp_clienthellos: 1,
    tcp_clienthello_after_udp_initial_ms: 101,
  });
});

test("missing TCP/UDP observations stay unknown and invalid phase bounds fail", () => {
  assert.equal(
    connectionTiming([], [1.1], { start: 1, end: 2 })
      .tcp_clienthello_after_udp_initial_ms,
    null,
  );
  assert.equal(connectionTiming([], [], null), null);
  assert.throws(
    () => connectionTiming([], [], { start: 2, end: 1 }),
    /invalid/,
  );
});
