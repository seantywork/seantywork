

#include "qs.h"
#include "qs_tls.h"

void print_help(){

    printf("keygen        : pq key generation \n");
    printf("encap         : pq key encap\n");
    printf("decap         : pq key decap\n");
    printf("sig           : pq signature \n");
//    printf("oqs-kem       : pq key encap/decap using liboqs \n");
//    printf("oqs-sig       : pq signature using liboqs \n");
    printf("cert-gen      : pq certificate generation \n");
    printf("cert-verify   : pq certificate verification \n");
    printf("tls           : pq tls \n");

}


#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0;
    
    if(argc != 2){
        printf("invalid argument\n");
        print_help();
        return -1;
    }
    if(qs_init() < 0){
        printf("init failed\n");
        return -1;
    }
    if(strcmp(argv[1], "keygen") == 0){
        if (qs_key_create() == 1) {
            fprintf(stderr, cGREEN "  keygen test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  keygen test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    } else if(strcmp(argv[1], "encap") == 0){
        if (qs_encap("./enc.bin", "./sec.bin") == 1) {
            fprintf(stderr, cGREEN "  encap test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  encap test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    }else if(strcmp(argv[1], "decap") == 0){
        if (qs_decap("./enc.bin", "./sec.bin") == 1) {
            fprintf(stderr, cGREEN "  decap test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  decap test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    } else if(strcmp(argv[1], "sig") == 0){
        if (qs_signature() == 1) {
            fprintf(stderr, cGREEN "  signature test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  signature test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    /*} else if(strcmp(argv[1], "oqs-kem") == 0){
        if (oqs_kem() == OQS_SUCCESS) {
            fprintf(stderr, cGREEN "  KEM test succeeded" cNORM "\n");
        } else {
            fprintf(stderr, cRED "  KEM test failed" cNORM "\n");
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    } else if (strcmp(argv[1], "oqs-sig") == 0){        
        if (oqs_signature() == OQS_SUCCESS) {
            fprintf(stderr, cGREEN "sig test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "sig test failed" cNORM "\n");
        }  */
    } else if (strcmp(argv[1], "cert-gen") == 0){
        if(qs_cert_create() == 1) {
            fprintf(stderr, cGREEN "cert create test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "cert create test failed" cNORM "\n");
        }
    }else if (strcmp(argv[1], "cert-verify") == 0){
        if(qs_cert_verify() == 1) {
            fprintf(stderr, cGREEN "cert verify test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "cert verify test failed" cNORM "\n");
        }
    } else if (strcmp(argv[1], "tls") == 0){
#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
        int res = qs_tlsnet(THIS_SIG_NAME, THIS_KEM_NAME, 0);
        if (res == 1) {
            fprintf(stderr, cGREEN "tls net test succeeded" cNORM "\n");
        } else {
            errcnt += 1;
            fprintf(stderr, cRED "tls net test failed" cNORM "\n");
        }
#else
        fprintf(stderr,
                "TLS-SIG handshake test not enabled. Update OpenSSL to more "
                "current version.\n");
#endif
    } else {
        printf("invalid argument: %s\n", argv[1]);
        print_help();
        return -1;
    }
    qs_exit();
    errcnt = errcnt * -1;
    return errcnt;
}