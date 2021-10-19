#ifndef WEBSOCKH_H
#define WEBSOCKH_H

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct _websockh_client {
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
} *websockh;

SSL_CTX *websockh_init_ssl_ctx();
websockh websockh_create_connection(const char *url, uint16_t port, const char *path, SSL_CTX *ssl_ctx);

uint8_t websockh_send_text(websockh client, char *buffer, uint64_t len);
uint8_t websockh_send(websockh client, void *buffer, uint64_t len, uint8_t opcode);
uint8_t websockh_send_pong(websockh client);

void *websockh_recv(websockh client, uint64_t *len, uint8_t *type_data);

void websockh_close_connection(websockh client);

#endif