Wire fingerprint fixtures cover Chrome 156 on Windows and Android, and Chrome 157 on iOS.

The iOS reference is checked against Chrome 157.0.8103.37 on iOS 27.0.1.
The supplied navigation capture omits HTTP/2 PRIORITY and uses Russian; the
fixture retains its SNI, authority, path, language and 273-byte HEADERS block.
The wire test sets Russian explicitly; the profile's default remains English.
Saved-file requests use different headers and do not replace navigation.
The supplied TLS captures have no PSK and validate fresh handshakes only.

The TLS section records the normalized HTTP/2 ClientHello. GREASE code points,
key material and ECH payload bytes are normalized. Chromium extension order is
permuted; WebKit extension order is fixed. Empty extension bodies have no trailing spaces.

The HTTP/2 section records SETTINGS, WINDOW_UPDATE and the first navigation
HEADERS frame. HPACK representation annotations are omitted; field names, values,
order and frame parameters are retained. The ephemeral authority port is replaced
with PORT. These are expected client wire snapshots, not independent raw browser captures.

Firefox 159 desktop uses the supplied browser JSON as its reference. Its TLS and
HTTP/2 parameters are shared across desktop systems; the navigation User-Agent
is normalized to Windows. SNI is retained for tls.peet.ws, matching that capture.
ECH GREASE cipher selection, config IDs and ciphertext are connection-dependent.
The Firefox payload length is additionally checked against the captured 240 bytes.
