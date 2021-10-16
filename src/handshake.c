#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "handshake.h"

void addHandshakeField(handshake_field fields, const char *key, uint32_t key_length, const char *value, uint32_t value_length){
	handshake_field field = fields->last, new_last;
	if (field == NULL) field = fields;

	char *buffer;

	field->key_length = key_length;
	buffer = calloc(key_length, 1);
	memcpy(buffer, key, key_length);
	field->key = buffer;

	field->value_length = value_length;
	buffer = calloc(value_length, 1);
	memcpy(buffer, value, value_length);
	field->value = buffer;

	new_last = calloc(1, sizeof(struct _handshake_field));

	field->next = new_last;
	fields->last = new_last;
}

void modifyHandshakeField(handshake_field fields, const char *key, uint32_t key_length, const char *value, uint32_t value_length){
	handshake_field field = fields;
	while (1){
		register void *ptr = field->next;
		if (ptr == NULL) return;

		if (key_length == field->key_length){
			if (memcmp(field->key, key, key_length) == 0) break;
		}
		field = ptr;
	}

	char *buffer = calloc(1, value_length);
	memcpy(buffer, value, value_length);
	free(field->value);
	field->value = buffer;
	field->value_length = value_length;
}

char *getHandshakeField(handshake_field fields, const char *key, uint32_t key_length, uint32_t *vl){
	handshake_field field = fields;
	while (1){
		register void *ptr = field->next;
		if (ptr == NULL) return NULL;

		
		if (key_length == field->key_length){
			if (memcmp(field->key, key, key_length) == 0){
				vl[0] = field->value_length;
				return field->value;
			}
		}
		field = ptr;
	}
	return NULL;
}

uint64_t calcHandshakeLenght(uint32_t header_length, handshake_field fields){
	handshake_field field = fields;
	uint64_t size = header_length + 2;

	while (1) {
		register void *ptr = field->next;
		if (ptr == NULL) break;

		size += field->value_length+field->key_length+4;
		field = ptr;
	}
	return size;
}

char *getHandshakeFrame(const char *header, uint32_t header_length, handshake_field fields, uint64_t length){
	uint64_t offset = 0;
	char *handshake = calloc(1, length);
	const char tl[2] = ": ", sep[2] = "\r\n";
	handshake_field field = fields;

	memcpy(handshake, header, header_length);
	offset += header_length;

	while (1){
		register void *ptr = field->next;
		if (ptr == NULL) break;

		register uint64_t len = field->key_length;
		memcpy(handshake + offset, field->key, len);
		offset += len;

		memcpy(handshake + offset, tl, 2);
		offset += 2;

		len = field->value_length;
		memcpy(handshake + offset, field->value, len);
		offset += len;

		memcpy(handshake + offset, sep, 2);
		offset += 2;
		
		field = ptr;
	}
	memcpy(handshake + offset, sep, 2);

	return handshake;
}

websocket_response_header parseHandshake(const char *buffer, uint64_t len){
	websocket_response_header header = calloc(1, sizeof(struct _websocket_response_header));
	handshake_field field = calloc(1, sizeof(struct _handshake_field));
	header->fields = field;

	char st_code_str[5] = {0};
	uint64_t x=0, a=0, b=0;
	uint64_t vl, kl, fn = 0;

	for (; x < len && buffer[x] >= 32; x++);

	header->header = calloc(1, x);
	header->header_length = x;
	memcpy(header->header, buffer, x);

	for (uint64_t y=0; y<x && buffer[y] != ' '; y++, a++);
	a++;
	for (uint64_t y=a+1; y<x; y++){
		if (buffer[y] == ' '){
			memcpy(st_code_str, buffer + a, y-a);
			header->status_code = atoi(st_code_str);
			break;
		}
	}
	for (; x<len; x++){
		if (buffer[x] < 32) continue;
		else a = x;

		for (; x<len && buffer[x] != ':'; x++);
		kl = x-a;

		for (; x<len && (buffer[x] == ':' || buffer[x] == ' '); x++);
		b = x;

		for (; x<len && buffer[x] >= 32; x++);
		vl = x-b;

		addHandshakeField(field, buffer + a, kl, buffer + b, vl);
		fn++;
	}
	header->fields_num = fn;
	return header;
}

void freeHandshakeField(handshake_field fields){
	handshake_field field = fields;
	while (1){
		register void *ptr = field->next;
		if (ptr == NULL) return;

		free(field->key);
		free(field->value);
		free(field);
		field = ptr;
	}
	free(field);
}