/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE

*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// open ssl related includes
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

// Socket related includes
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#ifndef DEBUG
	#define DEBUG 1
#endif

#if DEBUG == 1
	#define DEBUGPRINT(x, ...)	fprintf(stderr, "%d %s: " x "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
	#define DEBUGPRINT(x, ...)
#endif

// Macro for Keys/Certificates
#define CA_CERT "Infineon OPTIGA(TM) Trust M CA 300.pem"

// Macro for Engine
#define ENGINE_NAME "trustm_engine"

// Default IP/PORT
#define DEFAULT_IP		"127.0.0.1"
#define	DEFAULT_PORT		5000
#define SECURE_COMM		TLS_client_method()
//#define SECURE_COMM		DTLS_client_method()


//typedef
// For Socket
typedef enum {
	SOCKET_IS_NONBLOCKING,
	SOCKET_IS_BLOCKING,
	SOCKET_HAS_TIMED_OUT,
	SOCKET_HAS_BEEN_CLOSED,
	SOCKET_OPERATION_OK
} timeout_state;

//extern
extern	int waitpid();

// Function Protoyping
void doClientConnect(void);


int main (int argc, char *argv[])
{

	//Print Heading
	DEBUGPRINT("*****************************************");
	
	doClientConnect();

	return 0;
}

void doClientConnect(void)
{
	int 		err;
	int len, i,j;
	SSL_CTX		*ctx;
	SSL		*ssl;
	SSL_METHOD	*meth;
	uint8_t		buf[4096];
	
	int		sock;
	struct sockaddr_in	server_addr;

	short int	s_port = DEFAULT_PORT;

	//int		sockstate;

	uint8_t		s_ipaddr[] = DEFAULT_IP;

	DEBUGPRINT("s_ipaddr : %s", s_ipaddr);

	SSL_library_init();
	SSL_load_error_strings();

	meth = (SSL_METHOD*) SECURE_COMM;

	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if(!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL)){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	//~ SSL_CTX_set_verify_depth(ctx, 1);

	/*********************************************************************/
	// Setting the Socket
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); // IPPROTO_TCP
	if (sock == -1)
	{
		perror("socket");
		exit(1);
	}

	memset(&server_addr, '\0', sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(s_port);
	server_addr.sin_addr.s_addr=inet_addr((char *)s_ipaddr);

	// Connect to server
	DEBUGPRINT("Connecting to server ....");
	err = connect(sock, (struct sockaddr*)&server_addr,sizeof(server_addr));
	if ((err)==-1)
	{

		perror("Connection");
		err = close(sock);
		if (err == -1)
		{
			perror("close");
			exit(1);
		}		
		SSL_CTX_free(ctx);

		return;

	}

	DEBUGPRINT("Connected to %s, port :0x%.4x", s_ipaddr, server_addr.sin_port);

	/**********************************************************************/
	// TCP Connection is ready
	// Estabish the SSL Connection

	// Set verify depth to 1
	SSL_CTX_set_verify_depth(ctx,1);

	ssl = SSL_new(ctx);
	if (ssl == NULL) 
	{
		DEBUGPRINT("Exit");
		exit(1);
	}

	// Assign the socket into the SSL structure
	SSL_set_fd(ssl, sock);


	
	// SSL Perfrom Handshaking
	DEBUGPRINT("Performing Handshaking .....");
	err = SSL_connect(ssl);
	if (err== -1)
	{
		ERR_print_errors_fp(stderr);
		DEBUGPRINT("Connection Error!!!");
		exit(1);
	}

	DEBUGPRINT("Connection using : %s", SSL_get_cipher(ssl));
	DEBUGPRINT("                 : %s", SSL_get_version(ssl));	

	/**********************************************************************/
			j =0;
			while(j < 101)
			{
				j++;
				err = SSL_write(ssl, &j, 1);
				if (err==-1)
				{
					ERR_print_errors_fp(stderr);
				} 
				
				len = SSL_read(ssl, buf, sizeof(buf) - 1);
				err = SSL_get_error(ssl, len);

				if ((err != 0) && (len == 0))
				{
					DEBUGPRINT("disconnected!!!");
				}
				else
				{
					for(i=0;i<len;i++)
					{
						printf("%c",buf[i]);
					}
					printf("\n");
				}
				sleep(1);
			}

	DEBUGPRINT("Connection Closed!!!");

	/**********************************************************************/
	// SSL Close
	err = SSL_shutdown(ssl);
	if (err==-1)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	err = close(sock);

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	DEBUGPRINT("it works!!!!");
}

