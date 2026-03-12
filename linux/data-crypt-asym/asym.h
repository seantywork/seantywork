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
#include <openssl/dsa.h>
#include <openssl/param_build.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/trace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>


#define THIS_RSA_BITS 4096
#define THIS_EC_GROUP "prime256v1"



int key_pair_generate(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s, char* priv_key_path_c, char* pub_key_path_c, int bits);
int asym_encrypt(char* pub_key_path, char* enc_msg_path, int msg_len, char* msg);
int asym_decrypt(char* pub_key_path, char* priv_key_path, char* enc_msg_path, char* plain_msg);
int key_pair_generate_ec(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s, char* priv_key_path_c, char* pub_key_path_c);
int asym_shared_keygen_ec(char* key_path, char* peer_pub_key_path, char* skey_path);
int asym_shared_keycheck_ec(char* key_path, char* peer_pub_key_path, char* skey_path);
void signature();
void cert_create();
void cert_verify();
void cert_show();
void tls();




int sig_verify(BIO* cert_pem, BIO* intermediate_pem);

void cert_info(BIO* cert_pem);

unsigned char* char2hex(int arrlen, unsigned char* bytearray);

unsigned char* hex2char(unsigned char* hexarray);





#endif