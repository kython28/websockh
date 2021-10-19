# websockh
A simple websocket client library for C

# How to use?
If you fancy using my code, you need copy the files from 'src' folder to your project to use its functions. To use it, you don't need high knowledge, because the functions are very easy to use.

To connect to websocket server:
```C
// websockh websockh_create_connection(const char *url, uint16_t port, const char *path, SSL_CTX *ssl_ctx);
SSL_CTX *ssl_ctx = websockh_init_ssl_ctx(); // if you'll connect with "wss", you must set ssl_ctx param with some SSL_CTX*, else, NULL
websockh ws =  websockh_create_connection("stream.binance.com",  9443,  "/ws/btcusdt@trade",  ssl_ctx);
if (ws == NULL) ...
```
Well, now you can use all the functions. So, we'll see some examples... If you want to send something:
```C
// To send text
// uint8_t  websockh_send_text(websockh client,  char  *buffer,  uint64_t len);
websockh_send_text(ws, "Hi!", 3);

// To send something else
// uint8_t  websockh_send(websockh client,  void  *buffer,  uint64_t len,  uint8_t opcode);
void *buffer = malloc(784);
// Doing something with "buffer"
websockh_send(ws, buffer, 784, 2);
```
If you want to send pong . . .
```C
// uint8_t  websockh_send_pong(websockh client);
websockh_send_pong(ws);
```
If you want to recv data . . .
```C
// void  *websockh_recv(websockh client,  uint64_t  *len,  uint8_t  *type_data);
uint64_t size;
uint8_t opcode;
void *buffer = websockh_recv(ws, &size, &opcode);
```
And finally, if want to close connection . . .
```C
// void  websockh_close_connection(websockh client);
websockh_close_connection(ws);
// And if you are using ssl_ctx
SSL_CTX_free(ssl_ctx);
```
# Example
```C
// main.c
#include "src/websockh.h"
#include <stdio.h>

int main(){
	SSL_CTX *ssl_ctx = websockh_init_ssl_ctx();
	websockh ws = websockh_create_connection("stream.binance.com", 9443, "/ws/btcusdt@trade", ssl_ctx);
	if (ws == NULL) return  1;
	while (1){
		uint64_t len;
		uint8_t opcode;
		char *msg = websockh_recv(ws, &len, &opcode);
		if (msg){
			if (opcode == 9) websockh_send_pong(ws);
			else  if (opcode == 8) break;
			else{
				printf("%s\n", msg);
				printf("%ld %d\n", len, opcode);
			}
			free(msg);
		}else break; // It return NULL if there is some error
	}
	websockh_close_connection(ws);
	SSL_CTX_free(ssl_ctx);
	return 0;
}
```
```
gcc -c src/handshake.c -o handshake.o
gcc -c src/websockh.c -o websockh.o
gcc main.c websockh.o handshake.o -lssl -lcrypto -o main
```
