#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>

typedef struct _handshake_field {
	uint32_t key_length, value_length;
	char *key, *value;
	void *next, *last;
} *handshake_field;

typedef struct _websocket_response_header {
	char *header;
	uint32_t status_code, header_length, fields_num;
	handshake_field fields;
} *websocket_response_header;

void addHandshakeField(handshake_field fields, const char *key, uint32_t key_length, const char *value, uint32_t value_length);
void modifyHandshakeField(handshake_field fields, const char *key, uint32_t key_length, const char *value, uint32_t value_length);
char *getHandshakeField(handshake_field fields, const char *key, uint32_t key_length, uint32_t *vl);

uint64_t calcHandshakeLenght(uint32_t header_length, handshake_field fields);
char *getHandshakeFrame(const char *header, uint32_t header_length, handshake_field fields, uint64_t length);

websocket_response_header parseHandshake(const char *buffer, uint64_t len);

void freeHandshakeField(handshake_field field);
#endif