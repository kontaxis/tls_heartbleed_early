# TLS Heartbleed Early
This program sends an SSL 3 ClientHello message with the Heartbeat
extension and immediately requests a heartbeat from the server without
completing the TLS handshake.

RFC 5246 states that "a HeartbeatRequest message SHOULD NOT be sent during
handshakes. If a handshake is initiated while a HeartbeatRequest is still
in flight, the sending peer MUST stop the DTLS retransmission timer for it.
The receiving peer SHOULD discard the message silently, if it arrives
during the handshake."

However, servers linked to OpenSSL 1.0.1f will respond to such early
heartbeat requests. This makes them vulnerable to Heartbleed even if
they require client-side certificates to complete the TLS handshake.
Had OpenSSL correctly implemented the RFC this would not have been an
issue.
