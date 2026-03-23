#include "asym.h"


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
    int result = -1;
    char* priv_key_path = "./ca_priv.pem";
    char* pub_key_path = "./ca_pub.pem";
    char* priv_key_path_s = "./s_priv.pem";
    char* pub_key_path_s = "./s_pub.pem";
    char* priv_key_path_c = "./c_priv.pem";
    char* pub_key_path_c = "./c_pub.pem"; 
    char* enc_path = "./enc_msg.bin";
    char* plain_msg = "cryptoinc";
    int bits = THIS_RSA_BITS;
    char* shared_key_path = "./shared_key.bin";
    char* cert_path = "./ca.crt.pem";
    char* cert_path_s = "./srv.crt.pem";
    char* cert_path_c = "./cli.crt.pem";
    if(argc < 2){
        fprintf(stderr, "too few arguments\n");
        print_help();
        return -1;
    }
    if(strcmp(argv[1], "keygen") == 0){
        result = key_pair_generate(priv_key_path, pub_key_path, priv_key_path_s, pub_key_path_s, priv_key_path_c, pub_key_path_c, bits);   
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    } else if (strcmp(argv[1], "encrypt") == 0) {
        int plain_msg_len = strlen(plain_msg);
        result = asym_encrypt(pub_key_path, enc_path, plain_msg_len, plain_msg);
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    } else if (strcmp(argv[1], "decrypt") == 0) {
        char plain_msg[1024] = {0};
        int result = asym_decrypt(pub_key_path, priv_key_path, enc_path, plain_msg);
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    } else if(strcmp(argv[1], "ec-keygen") == 0){  
        result = key_pair_generate_ec(priv_key_path, pub_key_path, priv_key_path_s, pub_key_path_s, priv_key_path_c, pub_key_path_c);   
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    }  else if (strcmp(argv[1], "ec-derive") == 0) {
        result = asym_shared_keygen_ec(priv_key_path_s, pub_key_path, shared_key_path);
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    } else if (strcmp(argv[1], "ec-verify") == 0) {
        result = asym_shared_keycheck_ec(priv_key_path, pub_key_path_s, shared_key_path);
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }
    } else if (strcmp(argv[1], "sig") == 0){
        result = signature(priv_key_path, pub_key_path); 
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }  
    } else if (strcmp(argv[1], "cert-gen") == 0){
        result = cert_create(cert_path, priv_key_path, pub_key_path, cert_path_s, pub_key_path_s, cert_path_c, pub_key_path_c);
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }  
    } else if (strcmp(argv[1], "cert-verify") == 0){
        result = cert_verify(cert_path_s, cert_path);
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }  
    } else if (strcmp(argv[1], "tls") == 0){
        result = tls(cert_path, cert_path_s, priv_key_path_s, cert_path_c, priv_key_path_c);   
        if(result < 0){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }  
    } else {
        fprintf(stderr, "invalid argument\n");
        print_help();
        return -10;
    }
    return 0;
}