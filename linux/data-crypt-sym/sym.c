#include "sym.h"


int sym_keygen(char* key_path, char* iv_path, char* cbc_iv_path, char* auth_key_path){

    FILE* fp;
    int result = -1;
    unsigned char* key = gen_random_bytestream(KEYLEN);
    unsigned char* iv = gen_random_bytestream(IVLEN);
    unsigned char* cbc_iv = gen_random_bytestream(CBC_IVLEN);
    unsigned char* hex_key = char2hex(KEYLEN, key);
    unsigned char* hex_iv = char2hex(IVLEN, iv);
    unsigned char* hex_cbc_iv = char2hex(CBC_IVLEN, cbc_iv);
    unsigned char* auth_key = gen_random_bytestream(KEYLEN);
    unsigned char* hex_auth_key = char2hex(KEYLEN, auth_key);

    result = 1;
    fp = fopen(key_path, "w");
    fputs(hex_key, fp);
    fclose(fp);
    fp = fopen(iv_path, "w");
    fputs(hex_iv, fp);
    fclose(fp);
    fp = fopen(cbc_iv_path, "w");
    fputs(hex_cbc_iv, fp);
    fclose(fp);
    fp = fopen(auth_key_path, "w");
    fputs(hex_auth_key, fp);
    fclose(fp);

    free(key);
    free(iv);    
    free(cbc_iv);    
    free(hex_key);
    free(hex_iv);
    free(hex_cbc_iv);
    free(auth_key);
    free(hex_auth_key);

    return result;
}


int sym_encrypt_gcm(char* key_path, char* iv_path, int enc_len, char* enc_msg, char* enc_path, char* ad, char* tag_path){

    int result = -1;
    FILE* fp;
    EVP_CIPHER_CTX *ctx;
    int outlen, rv = 0;
    unsigned char outbuf[MAX_OUT] = {0};
    int adlen = strlen(ad);
    char gcm_key_hex[KEYLEN * 2 + 1];
    char gcm_iv_hex[IVLEN * 2 + 1];
    unsigned char gcm_tag[TAGLEN] = {0};
    unsigned char* gcm_key;
    unsigned char* gcm_iv;
    EVP_CIPHER* cipher = EVP_aes_256_gcm();
    unsigned char* outbuf_hex = NULL;
    unsigned char* tag_hex = NULL;

    fp = fopen(key_path, "r");
    fgets(gcm_key_hex, KEYLEN * 2 + 1, fp);
    fclose(fp);

    fp = fopen(iv_path, "r");
    fgets(gcm_iv_hex, IVLEN * 2 + 1, fp);
    fclose(fp);

    gcm_key = hex2char(&outlen, (unsigned char*)gcm_key_hex);
    gcm_iv = hex2char(&outlen, (unsigned char*)gcm_iv_hex);

    ctx = EVP_CIPHER_CTX_new();

    if(EVP_EncryptInit(ctx, cipher, NULL, NULL) != 1){
        printf("encrypt init failed\n");
        goto out;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, NULL) != 1){
        printf("set ivlen failed\n");
        goto out;
    }

    if(EVP_EncryptInit(ctx, NULL, gcm_key, gcm_iv) != 1){
        printf("encrypt init key, iv failed\n");
        goto out;
    }
    
    if(EVP_EncryptUpdate(ctx, NULL, &outlen, ad, adlen) != 1){
        printf("encrypt update len failed\n");
        goto out;
    }

    if(EVP_EncryptUpdate(ctx, outbuf, &outlen, enc_msg, enc_len) != 1){
        printf("encrypt update failed\n");
        goto out;
    }
    int tmp = outlen;
    printf("outlen: %d\n", outlen);
    rv = EVP_EncryptFinal(ctx, outbuf, &outlen);
    printf("encrypt rv: %d\n", rv);
    if(rv != 1){
        goto out;
    }
    outlen = tmp;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, gcm_tag) != 1){
        printf("get tag failed\n");
        goto out;
    }
    outbuf_hex = char2hex(outlen, outbuf);
    fp = fopen(enc_path, "w");
    fputs(outbuf_hex, fp);
    fclose(fp);
    tag_hex = char2hex(TAGLEN, gcm_tag);
    fp = fopen(tag_path, "w");
    fputs(tag_hex, fp);
    fclose(fp);
    result = 1;
out:
    if(ctx != NULL){
        EVP_CIPHER_CTX_free(ctx);
    }
    if(gcm_key != NULL){
        free(gcm_key);
    }
    if(gcm_iv != NULL){
        free(gcm_iv);
    }
    if(outbuf_hex != NULL){
        free(outbuf_hex);
    }
    if(tag_hex != NULL){
        free(tag_hex);
    }

    return result;

}

int sym_decrypt_gcm(char* key_path, char* iv_path, char* enc_path, char* ad, char* tag_path){

    FILE* fp;

    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher = EVP_aes_256_gcm();
	int outlen, tmplen, rv;
    int bin_outlen = 0;
    int adlen = strlen(ad);
    char inbuf[MAX_OUT] = {0};
    char outbuf[MAX_OUT] = {0};
    char dec_msg[MAX_OUT] = {0};
    char gcm_key_hex[KEYLEN * 2 + 1];
    char gcm_iv_hex[IVLEN * 2 + 1];
    char gcm_tag_hex[TAGLEN * 2 + 1];
    unsigned char* gcm_key;
    unsigned char* gcm_iv;
    unsigned char* gcm_tag;
    unsigned char* inbuf_bin;
    int result = -1;

    fp = fopen(key_path, "r");
    fgets(gcm_key_hex, KEYLEN * 2 + 1, fp);
    fclose(fp);


    fp = fopen(iv_path, "r");
    fgets(gcm_iv_hex, IVLEN * 2 + 1, fp);
    fclose(fp);

    fp = fopen(tag_path, "r");
    fgets(gcm_tag_hex, TAGLEN * 2 + 1, fp);
    fclose(fp);

    gcm_key = hex2char(&bin_outlen, (unsigned char*)gcm_key_hex);
    gcm_iv = hex2char(&bin_outlen, (unsigned char*)gcm_iv_hex);
    gcm_tag = hex2char(&bin_outlen, (unsigned char*)gcm_tag_hex);
    fp = fopen(enc_path, "r");
    fgets(inbuf, MAX_OUT, fp);
    fclose(fp);

    inbuf_bin = hex2char(&bin_outlen, (unsigned char*)inbuf);

    ctx = EVP_CIPHER_CTX_new();

    if(EVP_DecryptInit(ctx, cipher, NULL, NULL) != 1){
        printf("decrypt init failed\n");
        goto out;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, NULL) != 1){
        printf("set ivlen failed\n");
        goto out;
    }

    if(EVP_DecryptInit(ctx, NULL, gcm_key, gcm_iv) != 1){
        printf("decrypt init key, iv failed\n");
        goto out;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &outlen, ad, adlen) != 1){
        printf("decrypt update len failed\n");
        goto out;
    }
    if(EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf_bin, bin_outlen) != 1){
        printf("decrypt update failed\n");
        goto out;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, gcm_tag) != 1){
        printf("decrypt set tag failed\n");
        goto out;
    }
    rv = EVP_DecryptFinal(ctx, outbuf, &outlen);
    printf("decrypt rv: %d\n", rv);
    if(rv != 1){
        goto out;
    }
    strcpy(dec_msg, outbuf);
    printf("%s\n", dec_msg);
    result = 1;

out:
    if(ctx != NULL){
        EVP_CIPHER_CTX_free(ctx);
    }
    if(gcm_key != NULL){
        free(gcm_key);
    }
    if(gcm_iv != NULL){
        free(gcm_iv);
    }
    if(gcm_tag != NULL){
        free(gcm_tag);
    }
    if(inbuf_bin != NULL){
        free(inbuf_bin);
    }
    return result;
}


int sym_encrypt_cbc(char* key_path, char* iv_path, int enc_len, char* enc_msg, char* enc_path, char* auth_key_path, char* auth_data_path){

    FILE* fp;

    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int outlen, rv = 0;
    unsigned char outbuf[MAX_OUT] = {0};


    int aes_blocklen = BLOCKLEN;
    unsigned char* inbuf = NULL;
    char cbc_key_hex[KEYLEN * 2 + 1];
    char cbc_iv_hex[CBC_IVLEN * 2 + 1];
    char cbc_auth_hex[KEYLEN * 2 + 1];

    unsigned char* cbc_key;
    unsigned char* cbc_iv;
    unsigned char* cbc_auth;
    unsigned char *result = NULL;
    unsigned int resultlen = -1;
    int ciphertext_len;
    unsigned char* auth_result_hex = NULL;
    unsigned char* outbuf_hex = NULL;
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

    fp = fopen(key_path, "r");
    fgets(cbc_key_hex, KEYLEN * 2 + 1, fp);
    fclose(fp);

    fp = fopen(iv_path, "r");
    fgets(cbc_iv_hex, CBC_IVLEN * 2 + 1, fp);
    fclose(fp);

    fp = fopen(auth_key_path, "r");
    fgets(cbc_auth_hex, KEYLEN * 2 + 1, fp);
    fclose(fp);

    cbc_key = hex2char(&outlen, (unsigned char*)cbc_key_hex);
    cbc_iv = hex2char(&outlen, (unsigned char*)cbc_iv_hex);
    cbc_auth = hex2char(&outlen, (unsigned char*)cbc_auth_hex);
    result = HMAC(EVP_sha256(), cbc_auth, KEYLEN, enc_msg, enc_len, result, &resultlen);

    if(result == NULL){
        printf("hmac failed\n");
        goto out;
    } else {
        printf("hmac success\n");
    }
    auth_result_hex = char2hex(resultlen, result);
    fp = fopen(auth_data_path, "w");
    fputs(auth_result_hex, fp);
    fclose(fp);
    resultlen = 0;

    ctx = EVP_CIPHER_CTX_new();

    //EVP_CIPHER_CTX_set_padding(ctx, 0);
    //EVP_EncryptInit(ctx, cipher, cbc_key, cbc_iv);

    if(EVP_EncryptInit_ex(ctx, cipher, NULL, cbc_key, cbc_iv) != 1){
        printf("failed to encrypt init\n");
        goto out;
    }

    if(EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, enc_len) != 1){
        printf("failed to encrypt update\n");
        goto out;
    }
    ciphertext_len = outlen;
    rv = EVP_EncryptFinal(ctx, outbuf + outlen, &outlen);
    printf("encrypt rv: %d\n", rv);
    if(rv != 1){
        printf("failed to encrypt final\n");
        goto out;
    }
    ciphertext_len += outlen;
    outbuf_hex = char2hex(ciphertext_len, outbuf);
    fp = fopen(enc_path, "w");
    fputs(outbuf_hex, fp);
    fclose(fp);
    result = 1;
out:
    if(inbuf != NULL){
        free(inbuf);
    }
    if(ctx != NULL){
        EVP_CIPHER_CTX_free(ctx);
    }
    if(cbc_key != NULL){
        free(cbc_key);
    }
    if(cbc_iv != NULL){
        free(cbc_iv);
    }
    if(cbc_auth != NULL){
        free(cbc_auth);
    } 
    if(outbuf_hex != NULL){
        free(outbuf_hex);
    }
    if(auth_result_hex != NULL){
        free(auth_result_hex);
    }

    return result;

}


int sym_decrypt_cbc(char* key_path, char* iv_path, char* enc_path, char* auth_key_path, char* auth_data_path){

    FILE* fp;

    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher = EVP_aes_256_cbc();
	int outlen, tmplen, rv;
    int bin_outlen = 0;
    char inbuf[MAX_OUT] = {0};
    char outbuf[MAX_OUT] = {0};
    char dec_msg[MAX_OUT] = {0};

    char cbc_key_hex[KEYLEN * 2 + 1];
    char cbc_iv_hex[CBC_IVLEN * 2 + 1];
    char cbc_auth_hex[KEYLEN * 2 + 1];
    char cbc_auth_val_hex[1024 + 1];


    unsigned char* cbc_key;
    unsigned char* cbc_iv;
    unsigned char* cbc_auth;
    unsigned char* cbc_auth_val;

    unsigned char *hmac_result = NULL;
    unsigned int resultlen = -1;
    int result = -1;
    int plaintext_len;
    unsigned char* inbuf_bin = NULL;

    fp = fopen(key_path, "r");
    fgets(cbc_key_hex, KEYLEN * 2 + 1, fp);
    fclose(fp);


    fp = fopen(iv_path, "r");
    fgets(cbc_iv_hex, CBC_IVLEN * 2 + 1, fp);
    fclose(fp);

    fp = fopen(auth_key_path, "r");
    fgets(cbc_auth_hex, KEYLEN * 2 + 1, fp);
    fclose(fp);

    fp = fopen(auth_data_path, "r");
    fgets(cbc_auth_val_hex, 1024 + 1, fp);
    fclose(fp);

    cbc_key = hex2char(&bin_outlen, (unsigned char*)cbc_key_hex);
    cbc_iv = hex2char(&bin_outlen, (unsigned char*)cbc_iv_hex);
    cbc_auth = hex2char(&bin_outlen, (unsigned char*)cbc_auth_hex);
    cbc_auth_val = hex2char(&bin_outlen, (unsigned char*)cbc_auth_val_hex);
    fp = fopen(enc_path, "r");
    fgets(inbuf, MAX_OUT, fp);
    fclose(fp);

    inbuf_bin = hex2char(&bin_outlen, (unsigned char*)inbuf);
    ctx = EVP_CIPHER_CTX_new();

    //EVP_CIPHER_CTX_set_padding(ctx, 0);

    //EVP_DecryptInit(ctx, cipher, cbc_key, cbc_iv);

    if(EVP_DecryptInit_ex(ctx, cipher, NULL, cbc_key, cbc_iv) != 1){
        printf("decrypt init failed\n");
        goto out;
    } 
    if(EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf_bin, bin_outlen) != 1){
        printf("decrypt update failed\n");
        goto out;
    }
    plaintext_len = outlen;

    rv = EVP_DecryptFinal(ctx, outbuf + outlen, &outlen);
    printf("decrypt rv: %d\n", rv);
    if(rv != 1){
        goto out;
    }
    plaintext_len += outlen;
    strcpy(dec_msg, outbuf);
    hmac_result = HMAC(EVP_sha256(), cbc_auth, KEYLEN, dec_msg, plaintext_len, hmac_result, &resultlen);
    if(hmac_result == NULL){
        printf("hmac failed\n");
        goto out;
    } else {
        printf("hmac success\n");
    }
    if(memcmp(hmac_result, cbc_auth_val, KEYLEN) != 0){
        printf("authentication failed\n");
        goto out;
    } else {
        printf("authenticated\n");
    }
    result = 1;
out:
    if(ctx != NULL){
        EVP_CIPHER_CTX_free(ctx);
    }
    if(cbc_key != NULL){
        free(cbc_key);
    }
    if(cbc_iv != NULL){
        free(cbc_iv);
    }
    if(inbuf_bin != NULL){
        free(inbuf_bin);
    }
    return result;
}

unsigned char* gen_random_bytestream (size_t num_bytes){
    unsigned char *stream = malloc(num_bytes);
    getrandom(stream, num_bytes, 0);
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

        printf("%d: %2X ", i, n);

    }

    printf("\n");

    return chararray;
}
