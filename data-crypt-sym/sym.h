#ifndef _SYM_H_
#define _SYM_H_




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>

#define CBC 0
#define KEYBIT 256
#define KEYLEN KEYBIT / 8
#if CBC
#define IVLEN 128 / 8
#else 
#define IVLEN 12
#endif
#define TAGLEN 128 / 8

#define MAX_IN 256
#define MAX_OUT 1024
//#define PADDING 2

extern int howmany;

extern EVP_CIPHER* cipher;



int sym_keygen(char* key_path, char* iv_path);


int sym_encrypt(char* key_path, char* iv_path, int enc_len, char* enc_msg, char* enc_path, char* ad);



int sym_decrypt(char* key_path, char* iv_path, char* enc_path, char* dec_msg, char* ad);


unsigned char* gen_random_bytestream (size_t num_bytes);



unsigned char* char2hex(int arrlen, unsigned char* bytearray);

unsigned char* hex2char(int* arrlen, unsigned char* hexarray);








#endif