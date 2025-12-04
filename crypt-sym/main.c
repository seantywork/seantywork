#include "sym.h"



int howmany;

EVP_CIPHER* cipher;


int main(int argc, char** argv){

    if(argc < 2){
        fprintf(stderr, "too few arguments\n");
        return -1;
    }



    srand ((unsigned int) time (NULL));

    switch(KEYBIT){
        case 128: 
            cipher  = EVP_aes_128_gcm ();
            break;
        case 192: 
            cipher  = EVP_aes_192_gcm ();
            break;
        case 256: 
#if CBC
            cipher  = EVP_aes_256_cbc ();
            break;
#else
            cipher  = EVP_aes_256_gcm ();
            break;
#endif
        default:
            break;

    }


    if(strcmp(argv[1], "keygen") == 0){

        char* key_path = "./key.data";
        char* iv_path = "./iv.data";

        int result = sym_keygen(key_path, iv_path);


    } else if (strcmp(argv[1], "encrypt") == 0){

        char* key_path = "./key.data";
        char* iv_path = "./iv.data";
        char* ad = "vvvvvvvv";

        char* enc_msg = "cryptoinc";
        
        int enc_len = strlen(enc_msg);

        char* enc_path = "./enc.bin";

        int result = sym_encrypt(key_path, iv_path, enc_len, enc_msg, enc_path, ad);


    } else if (strcmp(argv[1], "decrypt") == 0){

        char* key_path = "./key.data";
        char* iv_path = "./iv.data";
        char* enc_path = "./enc.bin";
        char* ad = "vvvvvvvv";
        char dec_msg[MAX_OUT] = {0};

        int result = sym_decrypt(key_path, iv_path, enc_path, dec_msg, ad);

        printf("%s\n", dec_msg);


    } else {


        fprintf(stderr, "invalid argument\n");
        return -10;

    }
    printf("done\n");

    return 0;

}