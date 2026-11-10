// Keep real capability differences. Normalize only explicitly random GREASE
// and connection IDs, plus extension/version ordering with independent entropy.
export function parseEndpointJSON(text) {
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value !== "number" || Number.isSafeInteger(value)) return value;
    if (!context?.source)
      throw Error(
        "Exact endpoint integers require JSON.parse source context (Node 22+)",
      );
    return context.source;
  });
}

export function nativeFingerprint(data) {
  const settingsGrease = (id) => id >= 33 && (id - 33) % 31 === 0;
  const legacyMinimum = 0xff02de1a;
  const transportGrease = (p) =>
    p.id !== legacyMinimum &&
    (p.name === "GREASE" || BigInt(p.id) % 31n === 27n);
  const parameters = data.tls.extensions.find((e) => e.id === 57).data;
  const version = parameters.find((p) => p.id === 17)?.value;
  return {
    ja3n: data.tls.ja3n,
    client_connection_id_length: data.quic.client_connection_id_length,
    settings: data.http3.settings
      .filter((s) => !settingsGrease(s.id))
      .map((s) => [s.id, s.value]),
    generated_settings_grease: data.http3.settings.some((s) =>
      settingsGrease(s.id),
    ),
    header_order: data.http3.header_order,
    headers: data.http3.headers,
    transport_parameter_order: parameters.map((p) =>
      transportGrease(p) ? "GREASE" : p.id,
    ),
    transport_parameters: parameters
      .filter((p) => !transportGrease(p))
      .toSorted((a, b) => a.id - b.id)
      .map((p) => [
        p.id,
        p.id === 15
          ? "AUTO"
          : p.id === 17
            ? {
                ...version,
                available_versions: version.available_versions.toSorted(
                  (a, b) => String(a).localeCompare(String(b)),
                ),
              }
            : p.value,
      ]),
  };
}
