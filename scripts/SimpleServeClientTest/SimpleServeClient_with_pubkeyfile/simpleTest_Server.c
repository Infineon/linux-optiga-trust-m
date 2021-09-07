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
#include <time.h>

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
	#define DEBUGPRINT(x, ...)      fprintf(stderr, "%d %s: " x "\n",__LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
	#define DEBUGPRINT(x, ...)
#endif


#define SERVER_CERT "server1.crt"
#define SERVER_KEY "0xe0f1:server1.pub"
#define CA_CERT "OPTIGA_Trust_M_Infineon_Test_CA.pem"


// Macro for Engine
#define ENGINE_NAME "trustm_engine"

// Default IP/PORT
#define DEFAULT_IP              "127.0.0.1"
#define DEFAULT_PORT            5000
#define SECURE_COMM		TLS_server_method()
//#define SECURE_COMM		DTLS_server_method()

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
extern  int waitpid();

// Function Protoyping
void serverListen(void);
void doServerConnected(int,int);

int main (int argc, char *argv[])
{

	//Print Heading
	DEBUGPRINT("*****************************************");

	serverListen();

	return 0;
}

void serverListen(void)
{
	int                     err;
	int                     error=0;
	int                     pid;
	int                     listen_sock;
	int                     sock;
	struct sockaddr_in      sa_serv;
	struct sockaddr_in      sa_cli;
	size_t                  client_len;
	short int               s_port = DEFAULT_PORT;

	int                     connect=0;


	/*********************************************************************/
	// Setting the Socket
	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); // IPPROTO_TCP
	if (listen_sock == -1)
	{
		error=1;
	}

	memset(&sa_serv, '\0', sizeof(sa_serv));

	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(s_port);
	err = bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));
	if (err == -1)
	{
		error=1;
	}

	/* Wait for an incoming TCP connection */
	err = listen(listen_sock, 5);
	if (err == -1)
	{
		error=1;
	}
	client_len = sizeof(sa_cli);

	while (error == 0)
	{
		/* Socket for TCP/IP connection is created */
		DEBUGPRINT("Listening to incoming connection");
		sock = accept(listen_sock, (struct sockaddr*)&sa_cli,(socklen_t *) &client_len);
		if (sock == -1)
		{
			error=1;
			break;
		}

		DEBUGPRINT("Connection from %d.%d.%d.%d, port :0x%.4x",
				sa_cli.sin_addr.s_addr & 0x000000ff,
				(sa_cli.sin_addr.s_addr & 0x0000ff00) >> 8,
				(sa_cli.sin_addr.s_addr & 0x00ff0000) >> (8*2),
				(sa_cli.sin_addr.s_addr & 0xff000000) >> (8*3),
				sa_cli.sin_port);

		// Create Child process
		pid = fork();
		if (pid == -1)
		{
		    error=1;
		}


		if (pid == 0)
		{
			connect = getpid();
			close(listen_sock);
			doServerConnected(sock,connect);
			DEBUGPRINT("[%d] Return from Child", connect);
			error=1;
		}
	}

	// Close the Socket
	err = close(sock);
	if (err == -1)
	{
		error=1;
	}

	DEBUGPRINT("[%d] Leaving Routine!!!", connect);
}

void doServerConnected(int sock, int connect)
{
	int             err;
	int             len;
	int             error=0;
	clock_t		start, end;


	SSL_CTX         *ctx;
	SSL             *ssl;
	SSL_METHOD      *meth;

	char         buf[4096];

	// For Engine
	ENGINE          *e;
	EVP_PKEY        *pkey;
	UI_METHOD       *ui_method;
	EC_KEY *ecdh;

	do {
	    // Init OPENSSL
	    SSL_library_init();
	    SSL_load_error_strings();
	    
		meth = (SSL_METHOD*) SECURE_COMM;
	    ctx = SSL_CTX_new(meth);
	    
	    if (!ctx)
	    {
		ERR_print_errors_fp(stderr);
		exit(1);
	    }

	    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	    if (ecdh == NULL)
	    {
		DEBUGPRINT("ECDH Param error......... ");
	    }
	    SSL_CTX_set_tmp_ecdh(ctx,ecdh);


	    //Load and init Engine
	    ENGINE_load_builtin_engines();
	    e = ENGINE_by_id(ENGINE_NAME);
	    if(!e)
	    {
		DEBUGPRINT("Error loading Engine!!");
	    }
	    DEBUGPRINT("Engine ID : %s",ENGINE_get_id(e));

	    if(!ENGINE_init(e))
	    {
		DEBUGPRINT("Cannot Init TrustM Engine!!");
	    }
	    DEBUGPRINT("Init TrustM Engine. Ok");

	    if(!ENGINE_set_default(e, ENGINE_METHOD_ALL))
	    {
		DEBUGPRINT(" Cannot use TrustM Engine!");
	    }
	    DEBUGPRINT("Set Default Engine Ok.");

	    // Load key
	    ui_method = UI_OpenSSL();
	    pkey = ENGINE_load_private_key(e,SERVER_KEY,ui_method,NULL);
	    SSL_CTX_use_PrivateKey(ctx, pkey);

	    // Load the servr certificate into ctx
	    if(SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
	    {
		DEBUGPRINT("Load Certificate Fail");
		break;
	    }
	    DEBUGPRINT("Load Certificate ok");

	    // Check if Private Key Match Server Cert
	    if(!SSL_CTX_check_private_key(ctx))
	    {
		DEBUGPRINT("Private Key do not Match the Server Certificate!!!!");
		break;
	    }
	    DEBUGPRINT("Private Key Match the Server Certificate.");

	   // Setup to Verify Client
	   // Load CA cert
	   if(!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL))
	   {
		DEBUGPRINT("Load CA cert Fail");
		break;
	   }
	   DEBUGPRINT("Load CA cert ok");

	   // Set require Peer to verify cert
	   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	   // Set verify depth to 1
	   SSL_CTX_set_verify_depth(ctx,1);
	}while(0);

    if(error==0)
    {
	// Estabish the SSL Connection

	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
	    error = 1;
	}

	// Assign the socket into the SSL structure
	SSL_set_fd(ssl, sock);

	// SSL Perfrom Handshaking
	DEBUGPRINT("Performing Handshking ......... ");
	err = SSL_accept(ssl);
	switch(err)
	{
		case 1:
			DEBUGPRINT("Connection using : %s", SSL_get_cipher(ssl));
			DEBUGPRINT("                 : %s", SSL_get_version(ssl));
			DEBUGPRINT("++++++++++++++++++++++++++++++++++++++++++++++");

			start = clock();
			while(1)
			{
				len = SSL_read(ssl, buf, sizeof(buf) - 1);
				err = SSL_get_error(ssl, len);

				if ((err != 0) && (len == 0))
				{
				    end = clock();
				    if (((end-start)/1000000) > 5)
				    {
					DEBUGPRINT("[%d] Timeout !!",connect);
					break;
				    }
				}
				else
				{
					start = clock();
					DEBUGPRINT("[%d] Received : %d", connect, buf[0]);
					if (buf[0] > 100)
						break;

					sprintf(buf,"From Server [%d] : %.3d",connect, buf[0]);
					err = SSL_write(ssl, buf,strlen(buf));
					if (err==-1)
					{
						ERR_print_errors_fp(stderr);
					}
				}
			}
			break;
		case 0:
			DEBUGPRINT("Connection Refuse ");
			break;
		default:
			DEBUGPRINT("SSL Error!!! %d",err);
	}

	err = SSL_shutdown(ssl);
	DEBUGPRINT("Connection Closed!!!");
    }

    // Free the SSL object
    ENGINE_free(e);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    DEBUGPRINT("Leaving Routine!!!");
}
