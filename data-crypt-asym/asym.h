#ifndef _CRYPT_ASYM_H_
#define _CRYPT_ASYM_H_




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/trace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>




extern RSA *r;
extern BIGNUM *bne;
extern BIO *bp_public;
extern BIO *bp_private;

extern EVP_PKEY *pkey;


int key_pair_generate(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s, int bits);

int key_pair_generate_ec(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s);


int asym_encrypt(char* pub_key_path, char* enc_msg_path, int msg_len, char* msg);

int asym_decrypt(char* pub_key_path, char* priv_key_path, char* enc_msg_path, char* plain_msg);

int asym_shared_keygen_ec(char* key_path, char* pub_key_path, char* peer_pub_key_path, char* skey_path);

int asym_shared_keycheck_ec(char* key_path, char* pub_key_path, char* peer_pub_key_path, char* skey_path);


int asym_pipe(char* pub_key_path, char* priv_key_path, int msg_len, char* msg);



void cert_create();

void cert_verify();

void cert_show();

void signature();

void tls();



int sig_verify(BIO* cert_pem, BIO* intermediate_pem);

void cert_info(BIO* cert_pem);

unsigned char* char2hex(int arrlen, unsigned char* bytearray);

unsigned char* hex2char(unsigned char* hexarray);


void compare_two_arrays(int len, char* arr1, char* arr2);

void free_all();

void free_all_ec();


#endif