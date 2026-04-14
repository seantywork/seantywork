#include "sym.h"



int howmany;


void print_help(){
    printf("keygen  : \n");
    printf("enc-gcm : \n");
    printf("dec-gcm : \n");
    printf("enc-cbc : \n");
    printf("dec-cbc : \n"); 
}


int main(int argc, char** argv){
    if(argc < 2){
        fprintf(stderr, "too few arguments\n");
        print_help();
        return -1;
    }
    char* key_path = "./key.data";
    char* iv_path = "./iv.data";
    char* cbc_iv_path = "./cbc_iv.data";
    char* auth_key_path = "./auth_key.data";
    char* ad = "vvvvvvvv";
    char* enc_msg = "cryptoinc";
    int enc_len = strlen(enc_msg);
    char* enc_path = "./enc.bin";
    char* tag_path = "./tag.data";
    char* auth_data_path = "./auth.data";
    int result = 0;


    if(strcmp(argv[1], "keygen") == 0){
        result = sym_keygen(key_path, iv_path, cbc_iv_path, auth_key_path);
    } else if (strcmp(argv[1], "enc-gcm") == 0){
        result = sym_encrypt_gcm(key_path, iv_path, enc_len, enc_msg, enc_path, ad, tag_path);
    } else if (strcmp(argv[1], "dec-gcm") == 0){
        result = sym_decrypt_gcm(key_path, iv_path, enc_path, ad, tag_path);
    } else if (strcmp(argv[1], "enc-cbc") == 0){
        result = sym_encrypt_cbc(key_path, cbc_iv_path, enc_len, enc_msg, enc_path, auth_key_path, auth_data_path);
    } else if (strcmp(argv[1], "dec-cbc") == 0){
        result = sym_decrypt_cbc(key_path, cbc_iv_path, enc_path, auth_key_path, auth_data_path);
    } else {
        fprintf(stderr, "invalid argument: %s\n", argv[1]);
        print_help();
        return -10;
    }
    if(result != 1){
        printf("failed: %s\n", argv[1]);
    } else {
        printf("success: %s\n", argv[1]);
    }

    return 0;

}