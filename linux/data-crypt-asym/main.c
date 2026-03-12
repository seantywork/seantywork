#include "asym.h"


RSA *r = NULL;
BIGNUM *bne = NULL;
BIO *bp_public = NULL; 
BIO *bp_private = NULL;



static inline void print_help(){

    printf("keygen           : rsa generate key pair\n");
    printf("encrypt          : rsa encrypt using public key\n");
    printf("decrypt          : rsa decrypt using private key\n");

    printf("ec-keygen        : ec generate key pair\n");
    printf("ec-derive        : ec generate shared secret\n");
    printf("ec-verify        : ec verify shared secret\n");

    printf("sig              : signature sign and verification\n");
    printf("cert-gen         : rsa generate certificate\n");
    printf("cert-verify      : rsa verify vertificate\n");
    printf("tls              : tls communication\n");

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
        char* priv_key_path_c = "./c_priv.pem";
        char* pub_key_path_c = "./c_pub.pem"; 
        int bits = 4096;
        int result = key_pair_generate(priv_key_path, pub_key_path, priv_key_path_s, pub_key_path_s, priv_key_path_c, pub_key_path_c, bits);   
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
        char* priv_key_path_c = "./c_priv.pem";
        char* pub_key_path_c = "./c_pub.pem";        
        int result = key_pair_generate_ec(priv_key_path, pub_key_path, priv_key_path_s, pub_key_path_s, priv_key_path_c, pub_key_path_c);   
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    }  else if (strcmp(argv[1], "ec-derive") == 0) {
        char* priv_key_path = "./s_priv.pem";
        char* peer_pub_key_path = "./ca_pub.pem";
        char* shared_key_path = "./shared.bin";
        int result = asym_shared_keygen_ec(priv_key_path, peer_pub_key_path, shared_key_path);
    } else if (strcmp(argv[1], "ec-verify") == 0) {
        char* priv_key_path = "./ca_priv.pem";
        char* peer_pub_key_path = "./s_pub.pem";
        char* shared_key_path = "./shared.bin";
        int result = asym_shared_keycheck_ec(priv_key_path, peer_pub_key_path, shared_key_path);
    } else if (strcmp(argv[1], "sig") == 0){
        signature();   
    } else if (strcmp(argv[1], "cert-gen") == 0){
        cert_create();
    } else if (strcmp(argv[1], "cert-verify") == 0){
        cert_verify();
    } else if (strcmp(argv[1], "tls") == 0){
        tls();   
    } else {
        fprintf(stderr, "invalid argument\n");
        print_help();
        return -10;
    }
    return 0;
}