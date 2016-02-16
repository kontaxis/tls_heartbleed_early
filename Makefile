.PHONY: all clean

all: tls_heartbleed_early server

tls_heartbleed_early:
	gcc -Wall tls_heartbleed_early.c -o tls_heartbleed_early

server: dummy_ssl_server/openssl-1.0.1f
	gcc -Wall dummy_ssl_server/ssl_server.c      \
		-Idummy_ssl_server/openssl-1.0.1f/include/ \
		-Ldummy_ssl_server/openssl-1.0.1f/         \
		-lssl -lcrypto -ldl -o server           && \
	ln -s dummy_ssl_server/dummy-cert.pem .   && \
	ln -s dummy_ssl_server/dummy-key.pem  .

dummy_ssl_server/openssl-1.0.1f:
	cd dummy_ssl_server           && \
	tar zxf openssl-1.0.1f.tar.gz && \
	cd openssl-1.0.1f             && \
	./config && make              && \
	cd ../                        && \
	cd ../

clean:
	rm -f tls_heartbleed_early
	rm -f server dummy-cert.pem dummy-key.pem
	rm -rf dummy_ssl_server/openssl-1.0.1f
