#include "asym.h"


int key_pair_generate(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s, char* priv_key_path_c, char* pub_key_path_c, int bits){
    
    int ret = -1;
    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkey_s = NULL;
    EVP_PKEY *pkey_c = NULL;
    BIO *keybio = NULL;
    BIO *keybio_s = NULL;
    BIO *keybio_c = NULL;
    BIO *pubkeybio = NULL;
    BIO *pubkeybio_s = NULL;
    BIO *pubkeybio_c = NULL;
    EVP_PKEY_CTX *evpctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    EVP_PKEY_CTX *evpctx_s = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    EVP_PKEY_CTX *evpctx_c = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if(EVP_PKEY_keygen_init(evpctx) != 1){
        printf("failed to init 0\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(evpctx, bits) != 1){
        printf("failed to set bits 0\n");
        goto out;
    }
    if(EVP_PKEY_generate(evpctx, &pkey) != 1){
        printf("failed to generate 0\n");
        goto out;
    }
    if(EVP_PKEY_keygen_init(evpctx_s) != 1){
        printf("failed to init 1\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(evpctx_s, bits) != 1){
        printf("failed to set bits 1\n");
        goto out;
    }
    if(EVP_PKEY_generate(evpctx_s, &pkey_s) != 1){
        printf("failed to generate 1\n");
        goto out;
    }
    if(EVP_PKEY_keygen_init(evpctx_c) != 1){
        printf("failed to init 2\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(evpctx_c, bits) != 1){
        printf("failed to set bits 2\n");
        goto out;
    }
    if(EVP_PKEY_generate(evpctx_c, &pkey_c) != 1){
        printf("failed to generate 2\n");
        goto out;
    }
    keybio = BIO_new_file(priv_key_path, "wb");
    pubkeybio = BIO_new_file(pub_key_path, "wb");
    keybio_s = BIO_new_file(priv_key_path_s, "wb");
    pubkeybio_s = BIO_new_file(pub_key_path_s, "wb");
    keybio_c = BIO_new_file(priv_key_path_c, "wb");
    pubkeybio_c = BIO_new_file(pub_key_path_c, "wb");
    PEM_write_bio_PrivateKey(keybio, pkey,NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pubkeybio, pkey);
    PEM_write_bio_PrivateKey(keybio_s, pkey_s,NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pubkeybio_s, pkey_s);
    PEM_write_bio_PrivateKey(keybio_c, pkey_c,NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pubkeybio_c, pkey_c);
    ret = 1;
out:
    if(pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if(pkey_s != NULL){
        EVP_PKEY_free(pkey_s);
    }
    if(pkey_c != NULL){
        EVP_PKEY_free(pkey_c);
    }
    if(evpctx != NULL){
        EVP_PKEY_CTX_free(evpctx);
    }
    if(evpctx_s != NULL){
        EVP_PKEY_CTX_free(evpctx_s);
    }
    if(evpctx_c != NULL){
        EVP_PKEY_CTX_free(evpctx_c);
    }
    if(keybio != NULL){
        BIO_free(keybio);
    }
    if(keybio_s != NULL){
        BIO_free(keybio_s);
    }   
    if(keybio_c != NULL){
        BIO_free(keybio_c);
    }
    if(pubkeybio != NULL){
        BIO_free(pubkeybio);
    }
    if(pubkeybio_s != NULL){
        BIO_free(pubkeybio_s);
    }
    if(pubkeybio_c != NULL){
        BIO_free(pubkeybio_c);
    }
    if(libctx != NULL){
        OSSL_LIB_CTX_free(libctx);
    }
    return ret;
}

int key_pair_generate_ec(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s, char* priv_key_path_c, char* pub_key_path_c){
    int ret = -1;
    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkey_s = NULL;
    EVP_PKEY *pkey_c = NULL;
    BIO *keybio = NULL;
    BIO *keybio_s = NULL;
    BIO *keybio_c = NULL;
    BIO *pubkeybio = NULL;
    BIO *pubkeybio_s = NULL;
    BIO *pubkeybio_c = NULL;
    EVP_PKEY_CTX *evpctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    EVP_PKEY_CTX *evpctx_s = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    EVP_PKEY_CTX *evpctx_c = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if(EVP_PKEY_keygen_init(evpctx) != 1){
        printf("failed to init 0\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_group_name(evpctx, THIS_EC_GROUP) != 1){
        printf("failed to set group 0\n");
        goto out;
    }
    if(EVP_PKEY_generate(evpctx, &pkey) != 1){
        printf("failed to generate 0\n");
        goto out;
    }
    if(EVP_PKEY_keygen_init(evpctx_s) != 1){
        printf("failed to init 1\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_group_name(evpctx_s, THIS_EC_GROUP) != 1){
        printf("failed to set group 1\n");
        goto out;
    }
    if(EVP_PKEY_generate(evpctx_s, &pkey_s) != 1){
        printf("failed to generate 1\n");
        goto out;
    }
    if(EVP_PKEY_keygen_init(evpctx_c) != 1){
        printf("failed to init 2\n");
        goto out;
    }
    if(EVP_PKEY_CTX_set_group_name(evpctx_c, THIS_EC_GROUP) != 1){
        printf("failed to set group 2\n");
        goto out;
    }
    if(EVP_PKEY_generate(evpctx_c, &pkey_c) != 1){
        printf("failed to generate 2\n");
        goto out;
    }
    keybio = BIO_new_file(priv_key_path, "wb");
    pubkeybio = BIO_new_file(pub_key_path, "wb");
    keybio_s = BIO_new_file(priv_key_path_s, "wb");
    pubkeybio_s = BIO_new_file(pub_key_path_s, "wb");
    keybio_c = BIO_new_file(priv_key_path_c, "wb");
    pubkeybio_c = BIO_new_file(pub_key_path_c, "wb");
    PEM_write_bio_PrivateKey(keybio, pkey,NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pubkeybio, pkey);
    PEM_write_bio_PrivateKey(keybio_s, pkey_s,NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pubkeybio_s, pkey_s);
    PEM_write_bio_PrivateKey(keybio_c, pkey_c,NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pubkeybio_c, pkey_c);
    ret = 1;
out:
    if(pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if(pkey_s != NULL){
        EVP_PKEY_free(pkey_s);
    }
    if(pkey_c != NULL){
        EVP_PKEY_free(pkey_c);
    }
    if(evpctx != NULL){
        EVP_PKEY_CTX_free(evpctx);
    }
    if(evpctx_s != NULL){
        EVP_PKEY_CTX_free(evpctx_s);
    }
    if(evpctx_c != NULL){
        EVP_PKEY_CTX_free(evpctx_c);
    }
    if(keybio != NULL){
        BIO_free(keybio);
    }
    if(keybio_s != NULL){
        BIO_free(keybio_s);
    }   
    if(keybio_c != NULL){
        BIO_free(keybio_c);
    }
    if(pubkeybio != NULL){
        BIO_free(pubkeybio);
    }
    if(pubkeybio_s != NULL){
        BIO_free(pubkeybio_s);
    }
    if(pubkeybio_c != NULL){
        BIO_free(pubkeybio_c);
    }
    if(libctx != NULL){
        OSSL_LIB_CTX_free(libctx);
    }
    return ret;

}


int asym_encrypt(char* pub_key_path, char* enc_msg_path, int msg_len, char* msg){

    int result = -1;

    FILE* fp;
    EVP_PKEY* pub_key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    char enc_msg[1024] = {0};
    int enc_len = 0;
    char* err;
    unsigned char* enc_hex = NULL;

    fp = fopen(pub_key_path, "r");
    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    printf("original message: %s\n", msg);    
    if(EVP_PKEY_encrypt_init(ctx) != 1){
        printf("encrypt init failed\n");
        goto out;
    }
    if(EVP_PKEY_encrypt(ctx, enc_msg, &enc_len, msg, msg_len) != 1){
        printf("encrypt failed\n");
        goto out;
    }
    enc_hex = char2hex(enc_len, (unsigned char*)enc_msg);
    printf("enclen: %d\n", enc_len);
    fp = fopen(enc_msg_path, "w");
    fputs((char*)enc_hex, fp);
    fclose(fp);
    result = 1;
out:
    if(pub_key != NULL){
        EVP_PKEY_free(pub_key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }
    if(enc_hex != NULL){
        free(enc_hex);
    }
    return result;
}

int asym_decrypt(char* pub_key_path, char* priv_key_path, char* enc_msg_path, char* plain_msg){

    int result = -1;
    FILE* fp;
    EVP_PKEY* priv_key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    char enc_msg[2048] = {0};
    int enc_len = 2048;
    char dec_msg[2048] = {0};
    int dec_len = 0;
    char* err;
    unsigned char* enc_bin = NULL;

    fp = fopen(priv_key_path, "r");
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(enc_msg_path, "r");
    fgets(enc_msg, enc_len, fp);
    fclose(fp);
    enc_bin = hex2char((unsigned char*)enc_msg);
    enc_len = strlen(enc_msg) / 2;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if(EVP_PKEY_decrypt_init(ctx) != 1){
        printf("decrypt init failed\n");
        goto out;
    }
    if(EVP_PKEY_decrypt(ctx, dec_msg, &dec_len, enc_bin, enc_len) != 1){
        printf("decrypt failed\n");
        goto out;
    }
    memcpy(plain_msg, dec_msg, dec_len);
    printf("declen: %d\n", dec_len);
    printf("original message: %s\n", plain_msg);
    result = 1;
out:
    if(priv_key != NULL){
        EVP_PKEY_free(priv_key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }
    if(enc_bin != NULL){
        free(enc_bin);
    }
    return result;
}


int asym_shared_keygen_ec(char* key_path, char* peer_pub_key_path, char* skey_path){

    int result = -1;

    FILE* fp;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* peer_pub_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t skey[1024] = {0};
    int skeylen = 0;
    unsigned char* enc_hex = NULL;

    fp = fopen(key_path, "r");
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    /*
    fp = fopen(pub_key_path, "r");
    if(!PEM_read_PUBKEY(fp, &pkey, NULL, NULL)){
        printf("failed to get public key\n");
        return -1;
    }
    fclose(fp);
    */
    fp = fopen(peer_pub_key_path, "r");
    peer_pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if(EVP_PKEY_derive_init(ctx) != 1){
        printf("failed to derive init\n");
        return -1;
    }
    if(EVP_PKEY_derive_set_peer(ctx, peer_pub_key) != 1){
        printf("failed to set peer\n");
        return -1;
    }
    if(EVP_PKEY_derive(ctx, NULL, &skeylen) != 1){
        printf("failed to get skeylen\n");
        return -1;
    }
    if(EVP_PKEY_derive(ctx, skey, &skeylen) != 1){
        printf("failed to derive\n");
        return -1;
    }

    enc_hex = char2hex(skeylen, skey);
    fp = fopen(skey_path, "w");
    fputs((char*)enc_hex, fp);

    fclose(fp);
    printf("skey len: %d\n", skeylen);
    result = 1;
out:
    if(pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if(peer_pub_key != NULL){
        EVP_PKEY_free(peer_pub_key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }
    if(enc_hex != NULL){
        free(enc_hex);
    }
    return result;
}

int asym_shared_keycheck_ec(char* key_path, char* peer_pub_key_path, char* skey_path){


    int result = -1;
    FILE* fp = NULL;
    EVP_PKEY* keypair = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* peer_pub_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t skey[1024] = {0};
    int skeylen = 0;
    int peer_skeylen = 1024;

    uint8_t peer_skey[1024] = {0};
    unsigned char* peer_skey_bin = NULL;

    fp = fopen(key_path, "r");
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    /*
    fp = fopen(pub_key_path, "r");
    if(!PEM_read_PUBKEY(fp, &pkey, NULL, NULL)){
        printf("failed to get public key\n");
        return -1;
    }
    fclose(fp);
    */
    fp = fopen(peer_pub_key_path, "r");
    peer_pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if(EVP_PKEY_derive_init(ctx) != 1){
        printf("failed to derive init\n");
        goto out;
    }
    if(EVP_PKEY_derive_set_peer(ctx, peer_pub_key) != 1){
        printf("failed to set peer\n");
        goto out;
    }
    if(EVP_PKEY_derive(ctx, NULL, &skeylen) != 1){
        printf("failed to get skeylen\n");
        goto out;
    }
    if(EVP_PKEY_derive(ctx, skey, &skeylen) != 1){
        printf("failed to derive\n");
        goto out;
    }
    printf("skeylen: %d\n", skeylen);
    fp = fopen(skey_path, "r");
    fgets(peer_skey, peer_skeylen, fp);
    fclose(fp);

    peer_skey_bin = hex2char(peer_skey);

    if(memcmp(skey, peer_skey_bin, skeylen) != 0){
        printf("verify failed\n");
        goto out;
    }
    result = 1;
out:
    if(pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if(peer_pub_key != NULL){
        EVP_PKEY_free(peer_pub_key);
    }
    if(ctx != NULL){
        EVP_PKEY_CTX_free(ctx);
    }
    if(peer_skey_bin != NULL){
        free(peer_skey_bin);
    }
    return result;
}



int signature(char* key_path, char* pub_key_path){

    int result = -1;

    FILE* fp;
    EVP_PKEY_CTX* ctx_sign = NULL;
    EVP_PKEY_CTX* ctx_verify = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* pub_key = NULL;
    unsigned char *sig = NULL;
    unsigned char* hash = NULL;
    size_t siglen;
    // sha256 "hello"
    char* hashstr = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";


    fp = fopen(key_path, "r");

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    fp = fopen(pub_key_path, "r");
    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    ctx_sign = EVP_PKEY_CTX_new(pkey, NULL);
    if(ctx_sign == NULL){
		printf("ctx sign failed\n");
        goto out;
    }
    ctx_verify = EVP_PKEY_CTX_new(pub_key, NULL);
    if(ctx_verify == NULL){
		printf("ctx verify failed\n");
        goto out;
    }

    int hash_length = strlen(hashstr);
    hash_length = hash_length / 2;

    hash = hex2char(hashstr);
    if (EVP_PKEY_sign_init(ctx_sign) != 1){
		printf("signature init failed\n");
        goto out;
    }
    /*
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_sign, RSA_PKCS1_PADDING) != 1){
		printf("signature rsa padding failed\n");
        return;
    }
    */
    if (EVP_PKEY_CTX_set_signature_md(ctx_sign, EVP_sha256()) != 1){
		printf("signature md failed\n");
        goto out;
    }
    if (EVP_PKEY_sign(ctx_sign, NULL, &siglen, hash, hash_length) != 1){
		printf("signature prepare failed\n");
        goto out;
    }

    sig = malloc(siglen);
    if (sig == NULL){
		printf("signature malloc failed\n");
        goto out;
    }
    memset(sig, 0, siglen);
    if (EVP_PKEY_sign(ctx_sign, sig, &siglen, hash, hash_length) != 1){
		printf("signature sign failed\n");
        goto out;
    }
    printf("signed: siglen: %d, hashlen: %d\n", siglen, hash_length);
    if (EVP_PKEY_verify_init(ctx_verify) != 1){
		printf("signature verify init failed\n");
        goto out;
    }
    /*
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING) != 1){
		printf("signature verify rsa padding failed\n");
        return;
    }
    */
    if (EVP_PKEY_CTX_set_signature_md(ctx_verify, EVP_sha256()) != 1){
		printf("signature verify md failed\n");
        goto out;
    }

    int ret = EVP_PKEY_verify(ctx_verify, sig, siglen, hash, hash_length);

    printf("result: %d\n", ret);
    result = ret;
out:
    if(pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if(pub_key != NULL){
        EVP_PKEY_free(pub_key);
    }
    if(ctx_sign != NULL){
        EVP_PKEY_CTX_free(ctx_sign);
    }
    if(ctx_verify != NULL){
        EVP_PKEY_CTX_free(ctx_verify);
    }
    if(sig != NULL){
        free(sig);
    }
    if(hash != NULL){
        free(hash);
    }
    return result;
}


int cert_create(char* cert_file, char* priv_path, char* pub_path, char* cert_file_s, char* pub_path_s, char* cert_file_c, char* pub_path_c){

    int result = -1;
    time_t exp_ca;
    time(&exp_ca);
    exp_ca += 315360000;

    time_t exp_s;
    time(&exp_s);
    exp_s += 31536000;

    char* serial_ca = "6d530ea7d4a0f7745fea74dc700a2c23d6aca20e";
    char* serial_s = "5f4e186311429e8e08f3d6ff656d7e7233860c67";
    char* serial_c = "aea579f1326be4dbcd3738e99debfbace6311218";
    FILE* fp = NULL;

    X509* x509_ca = X509_new();
    X509* x509_s = X509_new();
    X509* x509_c = X509_new();
    EVP_PKEY* priv_key_ca = NULL;
    EVP_PKEY* pub_key_ca = NULL;
    EVP_PKEY* pub_key_s = NULL;
    EVP_PKEY* pub_key_c = NULL;
    X509V3_CTX extctx;
    X509_EXTENSION *extension_usage = NULL;
    X509_EXTENSION *extension_skid = NULL;
    X509_EXTENSION *extension_akid = NULL;

    X509V3_set_ctx_nodb(&extctx);

    //X509_NAME* ca_name = X509_NAME_new();
    //X509_NAME* s_name = X509_NAME_new();

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    ASN1_INTEGER* serial_asn1 = ASN1_INTEGER_new();
    ASN1_INTEGER* serial_asn1_s = ASN1_INTEGER_new();
    ASN1_INTEGER* serial_asn1_c = ASN1_INTEGER_new();
    AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
    akid->keyid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING *skid = NULL;
    X509_EXTENSION *extakid = NULL;
    X509_EXTENSION *extskid = NULL;
    BIGNUM* q = BN_new();
    BIGNUM* q_s = BN_new();
    BIGNUM* q_c = BN_new();
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ASN1_IA5STRING *ia5 = NULL;

    char *subject_alt_name = "localhost";
    char *subject_alt_name_c = "client";

    fp = fopen(priv_path, "r");
    priv_key_ca = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(pub_path, "r");
    pub_key_ca = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(pub_path_s, "r");
    pub_key_s = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(pub_path_c, "r");
    pub_key_c = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    X509_set_version(x509_ca, 2);
    BN_hex2bn(&q, serial_ca);
    serial_asn1 = BN_to_ASN1_INTEGER(q, serial_asn1);
    X509_set_serialNumber(x509_ca, serial_asn1);    
    if(X509_time_adj_ex(X509_getm_notBefore(x509_ca), 0, 0, 0) == NULL){
        printf("ca set time fail\n");
        goto out;
    }
    if(X509_time_adj_ex(X509_getm_notAfter(x509_ca), 0, 0, &exp_ca) == NULL){
        printf("ca set end time fail\n");
        goto out;
    }
    X509_NAME* ca_name = X509_get_subject_name(x509_ca);
    X509_NAME_add_entry_by_txt(ca_name, "CN" , MBSTRING_ASC, (unsigned char *)"localhost_ca", -1, -1, 0);    
    if (X509_set_issuer_name(x509_ca, ca_name) != 1){
        printf("ca set name fail\n");
        goto out;
    }
    if(X509_set_pubkey(x509_ca, pub_key_ca) != 1){
        printf("ca set pubkey fail\n");
        goto out;
    }
    X509_pubkey_digest(x509_ca, EVP_sha1(), md, &md_len);
    skid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(skid, md, md_len);
    extskid = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid);
    X509_add_ext(x509_ca, extskid, -1);
    ASN1_OCTET_STRING_set(akid->keyid, md, md_len);
    extakid = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
    X509_add_ext(x509_ca, extakid, -1);
    X509V3_set_ctx(&extctx, x509_ca, x509_ca, NULL, NULL, 0);
    extension_usage = X509V3_EXT_conf_nid(NULL, &extctx, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(x509_ca, extension_usage, -1);
    if(X509_sign(x509_ca, priv_key_ca, EVP_sha256()) == 0){
        printf("ca sign fail\n");
        goto out;
    }

    X509_set_version(x509_s, 2);
    BN_hex2bn(&q_s, serial_s);
    serial_asn1_s = BN_to_ASN1_INTEGER(q_s, serial_asn1_s);
    X509_set_serialNumber(x509_s, serial_asn1_s);
    if(X509_time_adj_ex(X509_getm_notBefore(x509_s), 0, 0, 0) == NULL){
        printf("s set time fail\n");
        goto out;
    }

    if(X509_time_adj_ex(X509_getm_notAfter(x509_s), 0, 0, &exp_s) == NULL){
        printf("s set end time fail\n");
        goto out;
    }
    X509_NAME* s_name = X509_get_subject_name(x509_s);
    X509_NAME_add_entry_by_txt(s_name ,"CN" , MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    if(X509_set_issuer_name(x509_s, ca_name) != 1){
        printf("s issuer name failed\n");
        goto out;
    }
    if(X509_set_pubkey(x509_s, pub_key_s) != 1){
        printf("s set pubkey fail\n");
        goto out;
    }
    X509_pubkey_digest(x509_s, EVP_sha1(), md, &md_len);
    ASN1_OCTET_STRING_free(skid);
    skid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(skid, md, md_len);
    extskid = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid);
    X509_add_ext(x509_s, extskid, -1);
    X509_add_ext(x509_s, extakid, -1);
    gens = sk_GENERAL_NAME_new_null();
    gen = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(ia5, subject_alt_name, strlen(subject_alt_name));
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    sk_GENERAL_NAME_push(gens, gen);
    X509_add1_ext_i2d(x509_s, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);
    if(X509_sign(x509_s, priv_key_ca, EVP_sha256()) == 0){
        printf("s sign fail\n");
        goto out;
    }


    X509_set_version(x509_c, 2);
    BN_hex2bn(&q_c, serial_c);
    serial_asn1_c = BN_to_ASN1_INTEGER(q_c, serial_asn1_c);
    X509_set_serialNumber(x509_c, serial_asn1_c);
    if(X509_time_adj_ex(X509_getm_notBefore(x509_c), 0, 0, 0) == NULL){
        printf("c set time fail\n");
        goto out;
    }
    if(X509_time_adj_ex(X509_getm_notAfter(x509_c), 0, 0, &exp_s) == NULL){
        printf("c set end time fail\n");
        goto out;
    }
    X509_NAME* c_name = X509_get_subject_name(x509_c);
    X509_NAME_add_entry_by_txt(c_name ,"CN" , MBSTRING_ASC, (unsigned char *)"client", -1, -1, 0);
    if(X509_set_issuer_name(x509_c, ca_name) != 1){
        printf("c issuer name failed\n");
        goto out;
    }
    if(X509_set_pubkey(x509_c, pub_key_c) != 1){
        printf("c set pubkey fail\n");
        goto out;
    }
    X509_pubkey_digest(x509_c, EVP_sha1(), md, &md_len);
    ASN1_OCTET_STRING_free(skid);
    skid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(skid, md, md_len);
    extskid = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid);
    X509_add_ext(x509_c, extskid, -1);
    X509_add_ext(x509_c, extakid, -1);
    gens = sk_GENERAL_NAME_new_null();
    gen = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(ia5, subject_alt_name_c, strlen(subject_alt_name_c));
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    sk_GENERAL_NAME_push(gens, gen);
    X509_add1_ext_i2d(x509_c, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);
    if(X509_sign(x509_c, priv_key_ca, EVP_sha256()) == 0){
        printf("c sign fail\n");
        goto out;
    }

    fp = fopen(cert_file, "wb");
    PEM_write_X509(fp, x509_ca);
    fclose(fp);
    fp = fopen(cert_file_s, "wb");
    PEM_write_X509(fp, x509_s);
    fclose(fp);
    fp = fopen(cert_file_c, "wb");
    PEM_write_X509(fp, x509_c);
    fclose(fp);

    result = 1;
out:
    if(x509_ca != NULL){
        X509_free(x509_ca);
    }
    if(x509_s != NULL){
        X509_free(x509_s);
    }
    if(x509_c != NULL){
        X509_free(x509_c);
    }
    if(priv_key_ca != NULL){
        EVP_PKEY_free(priv_key_ca);
    }
    if(pub_key_ca != NULL){
        EVP_PKEY_free(pub_key_ca);
    }
    if(pub_key_s != NULL){
        EVP_PKEY_free(pub_key_s);
    }
    if(pub_key_c != NULL){
        EVP_PKEY_free(pub_key_c);
    }
    if(serial_asn1 != NULL){
        ASN1_INTEGER_free(serial_asn1);
    }
    if(serial_asn1_s != NULL){
        ASN1_INTEGER_free(serial_asn1_s);
    }
    if(serial_asn1_c != NULL){
        ASN1_INTEGER_free(serial_asn1_c);
    }
    if(akid != NULL){
        if(akid->keyid != NULL){
            ASN1_OCTET_STRING_free(akid->keyid);
        }
        AUTHORITY_KEYID_free(akid);
    }
    if(skid != NULL){
        ASN1_OCTET_STRING_free(skid);
    }
    if(q != NULL){
        BN_free(q);
    }
    if(q_s != NULL){
        BN_free(q_s);
    }
    if(q_c != NULL){
        BN_free(q_c);
    }
    /*
    if(gens != NULL){
        sk_GENERAL_NAME_free(gens);
    }
    if(gen != NULL){
        GENERAL_NAME_free(gen);
    }
    if(ia5 != NULL){
        ASN1_IA5STRING_free(ia5);
    }
    */
    return result;
}


int cert_verify(char* cert_path_s, char* cert_path){

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 

    BIO* cert = NULL;
    BIO* intermediate = NULL;
    cert = BIO_new(BIO_s_file());
    intermediate = BIO_new(BIO_s_file());
    int ret = BIO_read_filename(cert, cert_path_s);
    ret = BIO_read_filename(intermediate, cert_path);
    //cert_info(cert);
    //cert_info(intermediate);
    int res = sig_verify(cert,intermediate);
    BIO_free_all(cert);
    BIO_free_all(intermediate);
    return res;

}

void cert_show(char* cert_path){
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 
    BIO* cert = NULL;
    cert = BIO_new(BIO_s_file());
    int ret = BIO_read_filename(cert, cert_path);
    cert_info(cert);
    BIO_free_all(cert);
}

int sig_verify(BIO* cert_pem, BIO* intermediate_pem){
    //BIO *b = BIO_new(BIO_s_mem());
    //BIO_puts(b, intermediate_pem);
    BIO* b = intermediate_pem;
    X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *signing_key=X509_get_pubkey(issuer);
    //BIO *c = BIO_new(BIO_s_mem());
    //BIO_puts(c, cert_pem);
    BIO* c = cert_pem;
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);
    int result = X509_verify(x509, signing_key);
    EVP_PKEY_free(signing_key);
    X509_free(x509);
    X509_free(issuer);
 
    return result;
}

void cert_info(BIO* cert_pem){
    //BIO *b = BIO_new(BIO_s_mem());
    //BIO_puts(b, cert_pem);
    BIO* b = cert_pem;
    X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out,"Subject: ");
    X509_NAME_print(bio_out,X509_get_subject_name(x509),0);
    BIO_printf(bio_out,"\n");
    BIO_printf(bio_out,"Issuer: ");
    X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
    BIO_printf(bio_out,"\n");
    //EVP_PKEY *pkey=X509_get_pubkey(x509);
    //EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
    //EVP_PKEY_free(pkey);
    //X509_signature_print(bio_out, x509->sig_alg, x509->signature);
    //BIO_printf(bio_out,"\n"); 
    BIO_free(bio_out);
    X509_free(x509);
}



static int create_tls_client(SSL *clientssl) {
    int i;
    unsigned char buf;
    size_t readbytes;
    int s;
    struct sockaddr_in addr;
    int port = 8080;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    int option = 1;
    //setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    int c = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    if(c < 0){
        printf("client connect failed\n");
        return 0;
    }
    int ret = SSL_set_fd(clientssl, s);
    if(ret != 1){
        printf("client ssl set fd failed\n");
        return 0;
    }
    ret = SSL_connect(clientssl);
    if(ret != 1){
        printf("client ssl connect failed\n");
        return 0;
    }
    X509* cert = SSL_get_peer_certificate(clientssl);
    if(cert == NULL) { 
        printf("client failed to get peer cert\n");
        exit(EXIT_FAILURE);
    } else {
        X509_free(cert); 
    } 
    printf("client ssl connected\n");
    ret = SSL_get_verify_result(clientssl);
    if (ret != X509_V_OK){
        printf("client ssl verify failed\n");
        return 0;
    };
    printf("client ssl verified\n");
    uint8_t wbuff[32] = {0};
    strcpy(wbuff, "hello");
    ret = SSL_write(clientssl, wbuff, 32);
    if(ret <= 0){
        printf("client ssl write failed\n");
        return 0;
    }
    sleep(3);
    return 1;
}

static void* create_tls_server(void* varg){
    int i;
    unsigned char buf;
    size_t readbytes;
    int s;
    struct sockaddr_in addr;
    socklen_t addrlen;

    int port = 8080;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    int option = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }
    SSL *serverssl = (SSL *)varg;
    addrlen = sizeof(addr);
    printf("server accept...\n");
    int c = accept(s, (struct sockaddr*)&addr, &addrlen);
    if(c < 0){
        printf("accept failed\n");
        exit(EXIT_FAILURE);
    }
    printf("server accepted\n");
    SSL_set_fd(serverssl, c);
    int ret = SSL_accept(serverssl);
    if(ret != 1){
        printf("SSL accept failed\n");
        exit(EXIT_FAILURE);
    }
    printf("server ssl accepted\n");
    uint8_t rbuff[32] = {0};
    ret = SSL_read(serverssl, rbuff, 32);
    if(ret <= 0){
        printf("server read failed\n");
        exit(EXIT_FAILURE);
    }
    if(strcmp(rbuff, "hello") == 0){
        printf("success: server hello\n");
    } else {
        printf("failed: server\n");
    }
    pthread_exit(NULL);
}

static void print_cn_name(const char* label, X509_NAME* const name){
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    do{
        if(!name) {
            break;
        }
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  {
            break;
        }
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) {
            break;
        }
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) {
            break;
        }
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0)) {
            break;
        }
        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;
        
    } while (0);
    if(utf8){
        OPENSSL_free(utf8);
    }
    if(!success){
        fprintf(stdout, "  %s: <not available>\n", label);
    }
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx){
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    print_cn_name("issuer cn: ", iname);
    print_cn_name("subject cn: ", sname);
    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    if(preverify == 0){
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if(err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }
    return preverify;
}

int tls(char *certfile_ca, char *certfile, char *privkeyfile, char *c_certfile, char *c_privkeyfile){
    int result = -1;
    int dtls_flag = 0;
    OSSL_LIB_CTX *libctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL_library_init();
    SSL_load_error_strings();
    CONF_modules_load(NULL, NULL, CONF_MFLAGS_IGNORE_MISSING_FILE);
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL){
        goto err;
    }
    if (dtls_flag) {
        serverctx = SSL_CTX_new_ex(libctx, NULL, DTLS_server_method());
        clientctx = SSL_CTX_new_ex(libctx, NULL, DTLS_client_method());
    } else {
        serverctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
        clientctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    }
    if (serverctx == NULL || clientctx == NULL)
        goto err;

    const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    
    SSL_CTX_set_options(clientctx, flags);
    SSL_CTX_set_options(serverctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
    if (dtls_flag) {
#ifdef DTLS1_3_VERSION
        if (!SSL_CTX_set_min_proto_version(serverctx, DTLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(serverctx, DTLS1_3_VERSION) ||
            !SSL_CTX_set_min_proto_version(clientctx, DTLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(clientctx, DTLS1_3_VERSION))
#endif
            goto err;
    } else {
        if (!SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION))
            goto err;
    }
    if (!SSL_CTX_load_verify_locations(clientctx, certfile_ca, NULL))
        goto err;

    SSL_CTX_set_verify(clientctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(clientctx, 5);
    printf("client load ca: %s\n", certfile_ca);
    if (!SSL_CTX_use_certificate_file(clientctx, c_certfile, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_use_PrivateKey_file(clientctx, c_privkeyfile, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_check_private_key(clientctx))
        goto err;

    printf("client file done: %s\n", c_certfile);
    if (!SSL_CTX_load_verify_locations(serverctx, certfile_ca, NULL))
        goto err;

    SSL_CTX_set_verify(serverctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(serverctx, 5);
    printf("server load ca: %s\n", certfile_ca);

    if (!SSL_CTX_use_certificate_file(serverctx, certfile, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_use_PrivateKey_file(serverctx, privkeyfile, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_check_private_key(serverctx))
        goto err;

    printf("server file done: %s\n", certfile);
    serverssl = SSL_new(serverctx);
    clientssl = SSL_new(clientctx);
    pthread_t tid;
    pthread_create(&tid, NULL, create_tls_server, (void*)serverssl);
    printf("server thread created\n");
    sleep(1);
    result = create_tls_client(clientssl);
err:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(serverctx);
    SSL_CTX_free(clientctx);
    OSSL_LIB_CTX_free(libctx);

    return result;
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




unsigned char* hex2char(unsigned char* hexarray){

    unsigned char* chararray;

    int hexlen = strlen(hexarray);

    int outstrlen = hexlen  / 2;

    chararray = (char*)malloc(outstrlen * sizeof(char));

    memset(chararray, 0, outstrlen * sizeof(char));

    unsigned int n = 0;

    for(int i = 0 ; i < outstrlen; i++){

        sscanf(hexarray + 2 * i, "%2x", &n);

        chararray[i] = n;

        printf("%d: %c%c ", i, hexarray[2 * i], hexarray[2 * i + 1]);

    }

    printf("\n");

    return chararray;
}




