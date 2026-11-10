// Wireshark nests short-header fields but emits long-header fields directly.
// Padding outside coalesced packets is a metadata object, not a 1-RTT packet.
export function quicPacketHeader(packet) {
  if (packet["quic.packet_length"] === undefined) return null;
  const header = packet["quic.short"] || packet;
  if (header["quic.header_form"] === undefined) return null;
  const type =
    packet["quic.long.packet_type"] === undefined
      ? "1rtt"
      : Number(BigInt(packet["quic.long.packet_type"]));
  const pn = header["quic.packet_number"];
  const length = header["quic.packet_number_length"];
  return {
    type,
    packet_number_bytes:
      pn === undefined || length === undefined
        ? null
        : Number(BigInt(length)) + 1,
  };
}

// Padding outside a long-header packet's encoded length has no AEAD protection.
// Inspect its bytes rather than treating Wireshark's generic label as randomness.
export function quicDatagramPadding(udp, packets) {
  const payload = Buffer.from(udp["udp.payload"].replaceAll(":", ""), "hex");
  const length = Number(udp["udp.length"]) - 8;
  if (payload.length !== length) throw Error("incomplete UDP payload");
  const end = packets.reduce(
    (sum, packet) => sum + Number(packet["quic.packet_length"] || 0),
    0,
  );
  if (end > length) throw Error("QUIC packet lengths exceed UDP payload");
  const tail = payload.subarray(end);
  const zeros = tail.reduce((count, byte) => count + Number(byte === 0), 0);
  return {
    bytes: tail.length,
    zero_bytes: zeros,
    nonzero_bytes: tail.length - zeros,
  };
}

// Decode the public control-stream prefix independently from Surf's encoders.
// Large QUIC integers are retained as strings instead of losing precision.
export function controlStreamSummary(hex) {
  const data = Buffer.from(hex.replaceAll(":", ""), "hex");
  let offset = 0;
  const read = () => {
    if (offset >= data.length) throw Error("truncated control varint");
    const length = 1 << (data[offset] >> 6);
    if (offset + length > data.length) throw Error("truncated control varint");
    let value = BigInt(data[offset] & 63);
    for (let i = 1; i < length; i++)
      value = (value << 8n) | BigInt(data[offset + i]);
    offset += length;
    return {
      value:
        value <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(value)
          : value.toString(),
      bytes: length,
    };
  };
  if (read().value !== 0) throw Error("not a control stream");
  const result = { bytes: data.length, frames: [], settings: [] };
  while (offset < data.length) {
    const type = read(),
      length = read();
    if (typeof length.value !== "number" || offset + length.value > data.length)
      throw Error("truncated control frame");
    const end = offset + length.value;
    result.frames.push({
      type: type.value,
      type_bytes: type.bytes,
      length_bytes: length.bytes,
      payload_bytes: length.value,
    });
    if (type.value === 4) {
      while (offset < end) {
        const id = read(),
          value = read();
        if (offset > end) throw Error("SETTINGS exceeds its frame length");
        result.settings.push({
          id: id.value,
          value: value.value,
          id_bytes: id.bytes,
          value_bytes: value.bytes,
        });
      }
    } else {
      offset = end;
    }
  }
  return result;
}
