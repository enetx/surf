import assert from "node:assert/strict";
import test from "node:test";
import { nativeFingerprint, parseEndpointJSON } from "./native-fingerprint.mjs";

test("legacy minimum and QUIC v2 capability cannot disappear as GREASE", () => {
  const data = {
    quic: { client_connection_id_length: 3 },
    http3: {
      settings: [
        { id: 33, value: 7 },
        { id: 1, value: 65536 },
      ],
      headers: [],
      header_order: [],
    },
    tls: {
      ja3n: "reference",
      extensions: [
        {
          id: 57,
          data: [
            { id: 0xff02de1a, value: "0x43e8" },
            { id: 27, value: "random" },
            { id: 15, value: "random cid" },
            {
              id: 17,
              value: {
                chosen_version: 1,
                available_versions: [1798521807, "GREASE", 1],
              },
            },
          ],
        },
      ],
    },
  };
  const result = nativeFingerprint(data);
  assert(result.transport_parameter_order.includes(0xff02de1a));
  assert.deepEqual(
    result.transport_parameters.find(([id]) => id === 0xff02de1a),
    [0xff02de1a, "0x43e8"],
  );
  assert.equal(result.transport_parameters[0][1], "AUTO");
  assert(
    result.transport_parameters[1][1].available_versions.includes(1798521807),
  );
  assert.deepEqual(result.settings, [[1, 65536]]);
  assert.equal(result.generated_settings_grease, true);
});

test("endpoint QUIC integers retain exact decimal bytes above 2^53", () => {
  assert.equal(
    parseEndpointJSON('{"id":4427419324614612011}').id,
    "4427419324614612011",
  );
  assert.equal(parseEndpointJSON('{"id":4278378010}').id, 4278378010);
});
