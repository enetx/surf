import assert from "node:assert/strict";
import test from "node:test";
import { peerAckObservations } from "./peer-ack-observations.mjs";

const packet = (number, dcid, frames = []) => ({
  "QUIC Connection information": { "quic.connection.number": number },
  "quic.dcid": dcid,
  frames,
});
const frame = (sequence = "0", flag = "0") => ({
  "quic.af.sequence_number": sequence,
  "quic.af.ack_eliciting_threshold": "2",
  "quic.af.request_max_ack_delay": "5000",
  "quic.af.reordering_threshold": flag,
});
const row = (...quic) => ({ _source: { layers: { quic } } });

test("attribute reused sequence zero to separate connections on one UDP socket", () => {
  const labels = new Map([
    ["aabb", "browser"],
    ["ccdd", "browser"],
  ]);
  const result = peerAckObservations(
    [
      row(packet("0", "aa:bb"), packet("1", "cc:dd")),
      row(
        packet("0", "ee:ff", [frame()]),
        packet("1", "00:11", [frame("0", "1")]),
      ),
    ],
    labels,
  );
  assert.deepEqual(
    result.map((r) => [r.connection, r.sequence, r.ignore_order]),
    [
      ["aabb", 0, false],
      ["ccdd", 0, true],
    ],
  );
  assert(result.every((r) => r.tolerance === 2 && r.max_ack_delay_us === 5000));
});

test("reject unbound frames and incompatible draft flags", () => {
  assert.throws(
    () => peerAckObservations([row(packet("0", "00", [frame()]))], new Map()),
    /attribution/,
  );
  assert.throws(
    () =>
      peerAckObservations(
        [row(packet("0", "00", [frame("0", "2")]))],
        new Map([["00", "browser"]]),
      ),
    /legacy/,
  );
});

test("coalesced 1-RTT packet inherits datagram connection metadata", () => {
  const result = peerAckObservations(
    [row(packet("0", "aa")), row(packet("0", "bb"), { frames: [frame()] })],
    new Map([["aa", "browser"]]),
  );
  assert.equal(result[0].connection, "aa");
});
