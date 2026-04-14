#ifndef _SYM_H_
#define _SYM_H_




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/random.h>
#include <time.h>

#define KEYBIT 256
#define KEYLEN KEYBIT / 8
#define BLOCKLEN 16

#define CBC_IVLEN (128 / 8)
#define IVLEN 12

#define TAGLEN 128 / 8

#define MAX_IN 256
#define MAX_OUT 1024
//#define PADDING 2

extern int howmany;

extern EVP_CIPHER* cipher;



int sym_keygen(char* key_path, char* iv_path, char* cbc_iv_path, char* auth_key_path);
int sym_encrypt_gcm(char* key_path, char* iv_path, int enc_len, char* enc_msg, char* enc_path, char* ad, char* tag_path);
int sym_encrypt_cbc(char* key_path, char* iv_path, int enc_len, char* enc_msg, char* enc_path, char* auth_key_path, char* auth_data_path);
int sym_decrypt_gcm(char* key_path, char* iv_path, char* enc_path, char* ad, char* tag_path);
int sym_decrypt_cbc(char* key_path, char* iv_path, char* enc_path, char* auth_key_path, char* auth_data_path);

unsigned char* gen_random_bytestream (size_t num_bytes);

unsigned char* char2hex(int arrlen, unsigned char* bytearray);

unsigned char* hex2char(int* arrlen, unsigned char* hexarray);





#endif
