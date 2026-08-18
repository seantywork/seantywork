#include "server.h"

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


int set_tlsch(int sock, SSL *ssl_con, SSL_CTX * ssl_ctx){

    if ((TLSCH_HEAD + 1) == MAX_CONN){
        return -1;
    }

	CLIENT_CTX[TLSCH_HEAD].sock = sock;
	CLIENT_CTX[TLSCH_HEAD].ssl = ssl_con;
    CLIENT_CTX[TLSCH_HEAD].ctx = ssl_ctx;

	TLSCH_HEAD += 1;

	return 0;
}


SSL * get_tlsch_ssl(int sock)
{

	int i;

	for(i = 0; i <= TLSCH_HEAD; i++) {
		if(CLIENT_CTX[i].sock == sock) {

			return CLIENT_CTX[i].ssl;

		}
	}

	return NULL;
}


SSL_CTX * get_tlsch_ctx(int sock)
{

	int i;

	for(i = 0; i <= TLSCH_HEAD; i++) {
		if(CLIENT_CTX[i].sock == sock) {

			return CLIENT_CTX[i].ctx;

		}
	}

	return NULL;
}

int release_tlsch(int sock){


    int i;
    int hit = 0;

	for(i = 0; i <= TLSCH_HEAD; i++) {
		if(CLIENT_CTX[i].sock == sock) {

            SSL_shutdown(CLIENT_CTX[i].ssl);
            SSL_free(CLIENT_CTX[i].ssl);
            SSL_CTX_free(CLIENT_CTX[i].ctx);
			hit = 1;
		}
	}


    if(hit == 1){

        TLSCH_HEAD -= 1;

        return 0;

    }else {

        return -1;

    }

}