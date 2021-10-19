#include "websockh.h"
#include "handshake.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <endian.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>


char *createSecWebsocket(){
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return NULL;

	char k[16];
	read(fd, k, 16);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, k, 16);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	close(fd);

	return (*bufferPtr).data;
}

int send_handshake(websockh client, const char *host, const char *path, uint8_t port, uint8_t ssl, int version){
	int ret = 0;
	handshake_field fields = calloc(1, sizeof(struct _handshake_field));

	uint64_t hdr_len = 15 + strlen(path);
	uint32_t vl;
	char *header = calloc(1, hdr_len+1), ver[5] = {0};
	sprintf(header, "GET %s HTTP/1.1\r\n", path);
	sprintf(ver, "%d", version);

	char *key = createSecWebsocket();

	addHandshakeField(fields, "Host", 4, host, strlen(host));
	addHandshakeField(fields, "Upgrade", 7, "websocket", 9);
	addHandshakeField(fields, "Connection", 10, "Upgrade", 7);
	addHandshakeField(fields, "Sec-WebSocket-Key", 17, key, strlen(key));
	addHandshakeField(fields, "Sec-WebSocket-Version", 21, ver, strlen(ver));
	
	char response[65536] = {0};
	char *handshake;
	uint64_t l;
	websocket_response_header res_hdr;
	l = calcHandshakeLenght(hdr_len, fields);
	handshake = getHandshakeFrame(header, hdr_len, fields, l);
	if (ssl){
		if (SSL_write(client->ssl, handshake, l) <= 0) ret = -1;
		else if (SSL_read(client->ssl, response, l) <= 0) ret = -1;
	}else{
		if (send(client->fd, handshake, l, 0) <= 0) ret = -1;
		else if (recv(client->fd, response, 65536, 0) <= 0) ret = -1;
	}

	if (ret >= 0){
		res_hdr = parseHandshake(response, strlen(response));
		if (res_hdr->status_code != 101){
			register char *version = getHandshakeField(res_hdr->fields, "Sec-WebSocket-Version", 21, &vl);
			if (version) ret = atoi(version);
		}
		freeHandshakeField(res_hdr->fields);
		free(res_hdr);
	}
	freeHandshakeField(fields);
	free(handshake);
	free(header);
	return ret;
}

SSL_CTX *websockh_init_ssl_ctx(){
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
	return ctx;
}

websockh websockh_create_connection(const char *url, uint16_t port, const char *path, SSL_CTX *ssl_ctx){
	websockh client;
	
	char ip[16];
	memset(ip, 0, 16);
	

	struct in_addr **addr_list;
	struct hostent *he = gethostbyname(url);
	if (he == NULL) return NULL;

	addr_list = (struct in_addr **)he->h_addr_list;
	strcpy(ip, inet_ntoa(*addr_list[0]));

	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	int fd, version = 25;
	client = calloc(1, sizeof(struct _websockh_client));
	client->ctx = ssl_ctx;
	uint8_t ssl = 0;
	if (ssl_ctx) ssl = 1;
	while (1){
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			free(client);
			return NULL;
		}
		if (connect(fd, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0) return NULL;

		client->fd = fd;
		if (ssl){
			client->ssl = SSL_new(ssl_ctx);
			SSL_set_fd(client->ssl, fd);
			if (SSL_connect(client->ssl) < 0){
				close(client->fd);
				free(client);
				client = NULL;
				break;
			}
		}

		version = send_handshake(client, url, path, port, ssl, version);
		if (version < 0){
			close(fd);
			if (ssl) SSL_free(client->ssl);
			free(client);
			client = NULL;
			break;
		}else if (version == 0) break;
		close(fd);
		if (ssl){
			SSL_free(client->ssl);
		}
	}
	return client;
}


#if __BYTE_ORDER == __LITTLE_ENDIAN
void convert_endian(uint8_t *a, uint8_t *b, uint8_t size){
	for (uint8_t x=0, y=size-1; x<size; x++, y--) a[x] = b[y];
}
#endif

uint8_t send_packet(websockh client, void *buffer, uint64_t len, uint8_t opcode){
	uint8_t hdr[10], fin = 0;
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t hdr_tmp[8];
	#endif
	uint64_t size, s2;

	SSL *ssl = client->ssl;
	if (ssl){
		for (uint64_t offset=0; offset<len; offset+=INT_MAX){
			if (offset+INT_MAX >= len) fin = 1;
			s2 = INT_MAX;
			if (s2+offset > len) s2 = len-offset;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
			hdr[0] = (fin << 7)|opcode;
			if (s2 < 126){
				hdr[1] = s2;
				size = 2;
			}else if (s2 < (1 << 16)){
				hdr[1] = 126;
				((uint16_t*)hdr_tmp)[0] = s2;
				size = 4;
				convert_endian(hdr + 2, hdr_tmp, 2);
			}else{
				hdr[1] = 127;
				((uint64_t*)hdr_tmp)[0] = s2;
				size = 10;
				convert_endian(hdr + 2, hdr_tmp, 8);
			}
			#else
			hdr[0] = (fin << 7)|opcode;
			if (s2 < 126){
				hdr_tmp[1] = s2;
				size = 2;
			}else if (len < (1 << 16)){
				hdr_tmp[1] = 126;
				((uint16_t*)&hdr_tmp[2])[0] = s2;
				size = 4;
			}else{
				hdr_tmp[1] = 127;
				((uint64_t*)&hdr_tmp[2])[0] = s2;
				size = 10;
			}
			#endif
			if (SSL_write(ssl, hdr, size) <= 0) return 1;
			if (SSL_write(ssl, buffer + offset, s2) <= 0) return 1;
		}
	}else{
		int fd = client->fd;
		#if __BYTE_ORDER == __LITTLE_ENDIAN
		hdr[0] = (1 << 7)|opcode;
		if (len < 126){
			hdr[1] = len;
			size = 2;
		}else if (len < (1 << 16)){
			hdr[1] = 126;
			((uint16_t*)hdr_tmp)[0] = len;
			size = 4;
			convert_endian(hdr + 2, hdr_tmp, 2);
		}else{
			hdr[1] = 127;
			((uint64_t*)hdr_tmp)[0] = len;
			size = 10;
			convert_endian(hdr + 2, hdr_tmp, 8);
		}
		#else
		hdr[0] = (1 << 7)|opcode;
		if (len < 126){
			hdr_tmp[1] = len;
			size = 2;
		}else if (len < (1 << 16)){
			hdr_tmp[1] = 126;
			((uint16_t*)&hdr_tmp[2])[0] = len;
			size = 4;
		}else{
			hdr_tmp[1] = 127;
			((uint64_t*)&hdr_tmp[2])[0] = len;
			size = 10;
		}
		#endif
		if (send(fd, hdr, size, 0) <= 0) return 1;
		if (send(fd, buffer, len, 0) <= 0) return 1;
	}
	return 0;
}

void *recv_pack(websockh client, uint64_t *len, uint8_t *opcode){
	void *buffer = NULL;
	char hdr[16];
	uint8_t hd = 1, l, fin = 0, mask;
	SSL *ssl = client->ssl;
	int fd = client->fd;
	uint64_t offset = 0, si = 0;
	len[0] = 0;
	while (!fin){
		offset += si;
		if (ssl){
			if (SSL_read(ssl, hdr, 2) <= 0) goto failed_recv_pack;
		}else{
			if (read(fd, hdr, 2) <= 0) goto failed_recv_pack;
		}
		fin = hdr[0];
		if (hd){
			opcode[0] = fin&((1 << 4) - 1);
			hd = 0;
		}
		fin = fin&(1 << 7);
		l = hdr[1];
		mask = l&(1 << 7);
		l = l&((1 << 7) - 1);
		if (l < 126) si = l;
		else if (l == 126){
			if (ssl){
				if (SSL_read(ssl, hdr, 2) <= 0) goto failed_recv_pack;
			}else{
				if (recv(fd, hdr, 2, 0) <= 0) goto failed_recv_pack;
			}

			#if __BYTE_ORDER == __LITTLE_ENDIAN
			convert_endian((uint8_t*)(hdr + 2), (uint8_t*)hdr, 2);
			si = ((uint16_t*)(hdr + 2))[0];
			#else
			si = ((uint16_t*)hdr)[0];
			#endif
		}else{
			if (ssl){
				if (SSL_read(ssl, hdr, 8) <= 0) goto failed_recv_pack;
			}else{
				if (recv(fd, hdr, 8, 0) <= 0) goto failed_recv_pack;
			}

			#if __BYTE_ORDER == __LITTLE_ENDIAN
			convert_endian((uint8_t*)(hdr + 8), (uint8_t*)hdr, 8);
			si = ((uint64_t*)(hdr + 8))[0];
			#else
			si = ((uint64_t*)hdr)[0];
			#endif
		}
		len[0] += si;

		if (mask){
			if (ssl){
				if (SSL_read(ssl, hdr, 4) <= 0) goto failed_recv_pack;
			}else{
				if (recv(fd, hdr, 4, 0) <= 0) goto failed_recv_pack;
			}
		}
		if (l > 0){
			buffer = realloc(buffer, len[0]);
			if (ssl){
				for (uint64_t x=0; x<si; x+=INT_MAX){
					register int le = INT_MAX;
					if (le+INT_MAX > si) le = si - x;

					if (SSL_read(ssl, buffer + offset + x, le) <= 0) goto failed_recv_pack;
				}
			}else{
				if (recv(fd, buffer + offset, si, 0) <= 0) goto failed_recv_pack;
			}
			if (mask){
				for (uint64_t x=0; x<si; x++){
					((uint8_t*)(buffer + offset))[x] ^= hdr[x%4];
				}
			}
		}
	}
	goto success_recv_pack;
	failed_recv_pack:
	if (buffer) free(buffer);
	len[0] = 0;
	buffer = NULL;
	success_recv_pack:
	return buffer;
}

uint8_t websockh_send_text(websockh client, char *buffer, uint64_t len){
	return send_packet(client, buffer, len, 1);
}

uint8_t websockh_send(websockh client, void *buffer, uint64_t len, uint8_t opcode){
	return send_packet(client, buffer, len, opcode);
}

uint8_t websockh_send_pong(websockh client){
	char pong[125];

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return 1;

	read(fd, pong, 125);
	close(fd);
	return send_packet(client, pong, 125, 10);
}

void *websockh_recv(websockh client, uint64_t *len, uint8_t *type_data){
	return recv_pack(client, len, type_data);
}

void websockh_close_connection(websockh client){
	if (client->ssl){
		SSL_free(client->ssl);
	}else{
		close(client->fd);
	}
	free(client);
}