#include "sym.h"


int sym_keygen(char* key_path, char* iv_path){

    FILE* fp;


    unsigned char* key = gen_random_bytestream(KEYLEN);

    unsigned char* iv = gen_random_bytestream(IVLEN);

    unsigned char* hex_key = char2hex(KEYLEN, key);

    unsigned char* hex_iv = char2hex(IVLEN, iv);


    fp = fopen(key_path, "w");

    fputs(hex_key, fp);

    fclose(fp);

    fp = fopen(iv_path, "w");

    fputs(hex_iv, fp);

    fclose(fp);
    

    free(key);
    free(iv);
    
    free(hex_key);
    free(hex_iv);

#if CBC

    unsigned char* auth_key = gen_random_bytestream(KEYLEN);

    unsigned char* hex_auth_key = char2hex(KEYLEN, auth_key);

    fp = fopen("./auth_key.data", "w");

    fputs(hex_auth_key, fp);

    fclose(fp);

    free(auth_key);

    free(hex_auth_key);

#endif

    return 0;
}


int sym_encrypt(char* key_path, char* iv_path, int enc_len, char* enc_msg, char* enc_path){

    FILE* fp;

    EVP_CIPHER_CTX *ctx;

    int outlen, rv = 0;
    unsigned char outbuf[MAX_OUT] = {0};
    

#if CBC

    int aes_blocklen = 16;

    unsigned char* inbuf = NULL;

    char cbc_key_hex[KEYLEN * 2 + 1];
    char cbc_iv_hex[IVLEN * 2 + 1];
    char cbc_auth_hex[KEYLEN * 2 + 1];


    unsigned char* cbc_key;

    unsigned char* cbc_iv;

    unsigned char* cbc_auth;

    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    int ciphertext_len;

    int padtest = enc_len % aes_blocklen;
    int padlen = 0;
    
    if(padlen != 0){

        padlen = aes_blocklen - padtest;
    }

    printf("padlen: %d\n", padlen);

    enc_len += padlen;

    inbuf = (unsigned char*)malloc(enc_len);

    memset(inbuf, 0, enc_len);

    memcpy(inbuf, enc_msg, enc_len - padlen);

    //strcpy(inbuf, enc_msg);

    fp = fopen(key_path, "r");

    fgets(cbc_key_hex, KEYLEN * 2 + 1, fp);

    fclose(fp);


    fp = fopen(iv_path, "r");

    fgets(cbc_iv_hex, IVLEN * 2 + 1, fp);

    fclose(fp);

    fp = fopen("./auth_key.data", "r");

    fgets(cbc_auth_hex, KEYLEN * 2 + 1, fp);

    fclose(fp);

    cbc_key = hex2char(&outlen, (unsigned char*)cbc_key_hex);

    cbc_iv = hex2char(&outlen, (unsigned char*)cbc_iv_hex);

    cbc_auth = hex2char(&outlen, (unsigned char*)cbc_auth_hex);

    ctx = EVP_CIPHER_CTX_new();

    //EVP_CIPHER_CTX_set_padding(ctx, 0);

    //EVP_EncryptInit(ctx, cipher, cbc_key, cbc_iv);

    EVP_EncryptInit_ex(ctx, cipher, NULL, cbc_key, cbc_iv);

    EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, enc_len);

    ciphertext_len = outlen;

    rv = EVP_EncryptFinal(ctx, outbuf + outlen, &outlen);
    
    printf("encrypt rv: %d\n", rv);

    ciphertext_len += outlen;

    unsigned char* outbuf_hex = char2hex(ciphertext_len, outbuf);

    fp = fopen(enc_path, "w");

    fputs(outbuf_hex, fp);

    fclose(fp);

    result = HMAC(EVP_sha256(), cbc_auth, KEYLEN, outbuf, outlen, result, &resultlen);

    if(result == NULL){

        printf("hmac failed\n");
    } else {

        printf("hmac success\n");
    }

    unsigned char* auth_result_hex = char2hex(resultlen, result);

    fp = fopen("./auth.data", "w");

    fputs(auth_result_hex, fp);

    fclose(fp);

    free(inbuf);

    EVP_CIPHER_CTX_free(ctx);
    free(cbc_key);
    free(cbc_iv);
    free(cbc_auth);

    free(outbuf_hex);
    free(auth_result_hex);
    
#else    

    char gcm_key_hex[KEYLEN * 2 + 1];
    char gcm_iv_hex[IVLEN * 2 + 1];

    unsigned char gcm_tag[TAGLEN] = {0};

    unsigned char* gcm_key;

    unsigned char* gcm_iv;

    unsigned char gcm_aad[8] = {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,};


    fp = fopen(key_path, "r");

    fgets(gcm_key_hex, KEYLEN * 2 + 1, fp);

    fclose(fp);


    fp = fopen(iv_path, "r");

    fgets(gcm_iv_hex, IVLEN * 2 + 1, fp);

    fclose(fp);

    gcm_key = hex2char(&outlen, (unsigned char*)gcm_key_hex);

    gcm_iv = hex2char(&outlen, (unsigned char*)gcm_iv_hex);


    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(ctx, cipher, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, NULL);

    EVP_EncryptInit(ctx, NULL, gcm_key, gcm_iv);

    
    // EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, 8);

    EVP_EncryptUpdate(ctx, outbuf, &outlen, enc_msg, enc_len);


    unsigned char* outbuf_hex = char2hex(outlen, outbuf);

    fp = fopen(enc_path, "w");

    fputs(outbuf_hex, fp);

    fclose(fp);

    rv = EVP_EncryptFinal(ctx, outbuf, &outlen);

    printf("encrypt rv: %d\n", rv);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, gcm_tag);

    
    unsigned char* tag_hex = char2hex(TAGLEN, gcm_tag);


    fp = fopen("./tag.data", "w");

    fputs(tag_hex, fp);

    fclose(fp);

    EVP_CIPHER_CTX_free(ctx);
    free(gcm_key);
    free(gcm_iv);

    free(outbuf_hex);
    free(tag_hex);
#endif

    return 0;

}



int sym_decrypt(char* key_path, char* iv_path, char* enc_path, char* dec_msg){

    FILE* fp;

    EVP_CIPHER_CTX *ctx;



	int outlen, tmplen, rv;
    int bin_outlen = 0;

    char inbuf[MAX_OUT] = {0};


    char outbuf[MAX_OUT] = {0};


#if CBC


    char cbc_key_hex[KEYLEN * 2 + 1];
    char cbc_iv_hex[IVLEN * 2 + 1];
    char cbc_auth_hex[KEYLEN * 2 + 1];
    char cbc_auth_val_hex[1024 + 1];


    unsigned char* cbc_key;
    unsigned char* cbc_iv;
    unsigned char* cbc_auth;
    unsigned char* cbc_auth_val;

    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    int plaintext_len;

    fp = fopen(key_path, "r");

    fgets(cbc_key_hex, KEYLEN * 2 + 1, fp);

    fclose(fp);


    fp = fopen(iv_path, "r");

    fgets(cbc_iv_hex, IVLEN * 2 + 1, fp);

    fclose(fp);

    fp = fopen("./auth_key.data", "r");

    fgets(cbc_auth_hex, KEYLEN * 2 + 1, fp);

    fclose(fp);

    fp = fopen("./auth.data", "r");

    fgets(cbc_auth_val_hex, 1024 + 1, fp);

    fclose(fp);

    cbc_key = hex2char(&bin_outlen, (unsigned char*)cbc_key_hex);

    cbc_iv = hex2char(&bin_outlen, (unsigned char*)cbc_iv_hex);

    cbc_auth = hex2char(&bin_outlen, (unsigned char*)cbc_auth_hex);

    cbc_auth_val = hex2char(&bin_outlen, (unsigned char*)cbc_auth_val_hex);

    fp = fopen(enc_path, "r");

    fgets(inbuf, MAX_OUT, fp);

    fclose(fp);

    unsigned char* inbuf_bin = hex2char(&bin_outlen, (unsigned char*)inbuf);

    result = HMAC(EVP_sha256(), cbc_auth, KEYLEN, inbuf_bin, bin_outlen, result, &resultlen);

    if(result == NULL){

        printf("hmac failed\n");

    } else {

        printf("hmac success\n");

    }

    if(memcmp(result, cbc_auth_val, 32) == 0){

        printf("authenticated\n");
    } else {
        printf("authentication failed\n");
    }



    ctx = EVP_CIPHER_CTX_new();

    //EVP_CIPHER_CTX_set_padding(ctx, 0);

    //EVP_DecryptInit(ctx, cipher, cbc_key, cbc_iv);

    EVP_DecryptInit_ex(ctx, cipher, NULL, cbc_key, cbc_iv);

    printf("%d\n", bin_outlen);

    rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf_bin, bin_outlen);

    printf("decrypt update rv: %d\n", rv);

    plaintext_len = outlen;

    rv = EVP_DecryptFinal(ctx, outbuf + outlen, &outlen);
    
    plaintext_len += outlen;

    strcpy(dec_msg, outbuf);

    printf("decrypt rv: %d\n", rv);

    EVP_CIPHER_CTX_free(ctx);
    free(cbc_key);
    free(cbc_iv);


    free(inbuf_bin);

#else 



    
    char gcm_key_hex[KEYLEN * 2 + 1];
    char gcm_iv_hex[IVLEN * 2 + 1];

    char gcm_tag_hex[TAGLEN * 2 + 1];

    unsigned char* gcm_key;

    unsigned char* gcm_iv;

    unsigned char* gcm_tag;

    unsigned char gcm_aad[8] = {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,};


    fp = fopen(key_path, "r");

    fgets(gcm_key_hex, KEYLEN * 2 + 1, fp);

    fclose(fp);


    fp = fopen(iv_path, "r");

    fgets(gcm_iv_hex, IVLEN * 2 + 1, fp);

    fclose(fp);

    fp = fopen("./tag.data", "r");

    fgets(gcm_tag_hex, TAGLEN * 2 + 1, fp);

    fclose(fp);

    gcm_key = hex2char(&bin_outlen, (unsigned char*)gcm_key_hex);

    gcm_iv = hex2char(&bin_outlen, (unsigned char*)gcm_iv_hex);

    gcm_tag = hex2char(&bin_outlen, (unsigned char*)gcm_tag_hex);

    fp = fopen(enc_path, "r");

    fgets(inbuf, MAX_OUT, fp);

    fclose(fp);


    unsigned char* inbuf_bin = hex2char(&bin_outlen, (unsigned char*)inbuf);


    ctx = EVP_CIPHER_CTX_new();


    EVP_DecryptInit(ctx, cipher, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, NULL);

    EVP_DecryptInit(ctx, NULL, gcm_key, gcm_iv);

    //EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, 8);

    printf("%d\n", bin_outlen);

    EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf_bin, bin_outlen);



    strcpy(dec_msg, outbuf);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, gcm_tag);

    rv = EVP_DecryptFinal(ctx, outbuf, &outlen);

    printf("decrypt rv: %d\n", rv);


    EVP_CIPHER_CTX_free(ctx);
    free(gcm_key);
    free(gcm_iv);
    free(gcm_tag);

    free(inbuf_bin);

#endif
    return 0;
}


unsigned char* gen_random_bytestream (size_t num_bytes){
  
  unsigned char *stream = malloc (num_bytes);

  size_t i;

  for (i = 0; i < num_bytes; i++){

    stream[i] = rand();
  
  }

  return stream;
}





unsigned char* char2hex(int arrlen, unsigned char* bytearray){

    unsigned char* hexarray;

    int hexlen = 2;

    int outstrlen = hexlen * arrlen + 1;

    hexarray = (char*)malloc(outstrlen * sizeof(char));

    memset(hexarray, 0, outstrlen * sizeof(char));

    unsigned char* ptr = hexarray;

    for(int i = 0 ; i < arrlen; i++){

        sprintf(ptr + 2 * i, "%02X", bytearray[i]);

        printf("%d: %c%c ", i, ptr[2 * i], ptr[2 * i + 1]);
    }

    printf("\n");

    return hexarray;
}




unsigned char* hex2char(int* arrlen, unsigned char* hexarray){

    *arrlen = 0;

    unsigned char* chararray;

    int hexlen = strlen(hexarray);

    int outstrlen = hexlen  / 2;

    chararray = (char*)malloc(outstrlen * sizeof(char));

    memset(chararray, 0, outstrlen * sizeof(char));

    unsigned int n = 0;

    for(int i = 0 ; i < outstrlen; i++){

        sscanf(hexarray + 2 * i, "%2x", &n);

        chararray[i] = n;

        *arrlen += 1;

        printf("%d: %c%c %d %x ", i, hexarray[2 * i], hexarray[2 * i + 1], n, chararray[i]);

    }

    printf("\n");

    return chararray;
}
