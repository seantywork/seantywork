#include "asym.h"


RSA *r = NULL;
BIGNUM *bne = NULL;
BIO *bp_public = NULL; 
BIO *bp_private = NULL;



static inline void print_help(){

    printf("keygen           : \n");
    printf("encrypt          : \n");
    printf("decrypt          : \n");

    printf("ec-keygen        : \n");
    printf("ec-gen-shared    : \n");
    printf("ec-check-shared  : \n");

    printf("cert-gen         : \n");
    printf("cert-verify      : \n");

    printf("ec-signature     : \n");

    printf("tls              : \n");

}


int main(int argc, char** argv){

    if(argc < 2){
        fprintf(stderr, "too few arguments\n");
        print_help();
        return -1;
    }

    if(strcmp(argv[1], "keygen") == 0){


        char* priv_key_path = "./ca_priv.pem";
        char* pub_key_path = "./ca_pub.pem";
        char* priv_key_path_s = "./s_priv.pem";
        char* pub_key_path_s = "./s_pub.pem";
        int bits = 4096;
        
        int result = key_pair_generate(priv_key_path, pub_key_path, priv_key_path_s, pub_key_path_s, bits);   

        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }

    } else if (strcmp(argv[1], "encrypt") == 0) {
        

        char* pub_key_path = "./ca_pub.pem";
        char* enc_path = "./enc_msg.bin";

        char* plain_msg = "cryptoinc";
        int plain_msg_len = strlen(plain_msg);

        int result = asym_encrypt(pub_key_path, enc_path, plain_msg_len, plain_msg);


    } else if (strcmp(argv[1], "decrypt") == 0) {

        char* priv_key_path = "./ca_priv.pem";
        char* pub_key_path = "./ca_pub.pem";
        char* enc_path = "./enc_msg.bin";

        char plain_msg[1024] = {0};
        

        int result = asym_decrypt(pub_key_path, priv_key_path, enc_path, plain_msg);

        printf("%s\n", plain_msg);

    } else if(strcmp(argv[1], "ec-keygen") == 0){


        char* priv_key_path = "./ca_priv.pem";
        char* pub_key_path = "./ca_pub.pem";
        char* priv_key_path_s = "./s_priv.pem";
        char* pub_key_path_s = "./s_pub.pem";
        
        
        int result = key_pair_generate_ec(priv_key_path, pub_key_path, priv_key_path_s, pub_key_path_s);   

        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }

    }  else if (strcmp(argv[1], "ec-gen-shared") == 0) {

        char* priv_key_path = "./s_priv.pem";
        char* pub_key_path = "./s_pub.pem";
        char* peer_pub_key_path = "./ca_pub.pem";
        char* shared_key_path = "./shared.bin";



        int result = asym_shared_keygen_ec(priv_key_path, pub_key_path, peer_pub_key_path, shared_key_path);


    } else if (strcmp(argv[1], "ec-check-shared") == 0) {

        char* priv_key_path = "./ca_priv.pem";
        char* pub_key_path = "./ca_pub.pem";
        char* peer_pub_key_path = "./s_pub.pem";
        char* shared_key_path = "./shared.bin";

        int result = asym_shared_keycheck_ec(priv_key_path, pub_key_path, peer_pub_key_path, shared_key_path);


    }  else if (strcmp(argv[1], "cert-gen") == 0){

        cert_create();

    } else if (strcmp(argv[1], "cert-verify") == 0){

        cert_verify();

    } else if (strcmp(argv[1], "ec-signature") == 0){

        signature();   
    
    }else if (strcmp(argv[1], "tls") == 0){

        tls();   
    
    }  else {

        fprintf(stderr, "invalid argument\n");
        print_help();
        return -10;
    }

    printf("done\n");

    return 0;
}