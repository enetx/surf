import assert from "node:assert/strict";
import { test } from "node:test";
import { ackObservations } from "./ack-observations.mjs";

const sent = (connection, packet_number, eliciting = true) => ({
  connection,
  direction: "sent",
  packet_number,
  eliciting,
});
const ack = (connection, ack_ranges) => ({
  connection,
  direction: "received",
  ack_ranges,
  ack_delay_ns: 2000000,
});

test("reconnected packet numbers have independent ACK and duplicate state", () => {
  const result = ackObservations([
    sent("a", 0),
    sent("b", 0),
    sent("a", 1),
    sent("b", 1),
    ack("a", [[0, 1]]),
    ack("b", [[0, 1]]),
    ack("a", [[0, 1]]),
  ]);
  assert.equal(result.connections, 2);
  assert.equal(result.server_ack_eliciting_packets, 4);
  assert.deepEqual(result.early, [2, 2]);
  assert.deepEqual(result.delays, [2, 2]);
});

test("transition is relative to each connection and ACK ranges stay bounded", () => {
  const result = ackObservations([
    sent("a", 10, false),
    sent("b", 5000, false),
    sent("a", 109),
    sent("b", 5099),
    ack("a", [[0, Number.MAX_SAFE_INTEGER]]),
    ack("b", [[0, Number.MAX_SAFE_INTEGER]]),
    sent("a", 110),
    sent("b", 5100),
    ack("a", [[0, Number.MAX_SAFE_INTEGER]]),
    ack("b", [[0, Number.MAX_SAFE_INTEGER]]),
  ]);
  assert.deepEqual(result.early, [1, 1]);
  assert.deepEqual(result.late, [1, 1]);
  assert.equal(result.server_ack_eliciting_packets, 4);
});
