#include "asym.h"



int key_pair_generate(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s, int bits){


	int ret = 0;

	unsigned long e = RSA_F4;


	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		free_all();
        return -1;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		free_all();
        return -2;
	}


	bp_private = BIO_new_file(priv_key_path, "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
	if(ret != 1){
		free_all();
        return -3;
	}


	bp_public = BIO_new_file(pub_key_path, "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
		free_all();
        return -4;
	}

    free_all();



	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		free_all();
        return -1;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		free_all();
        return -2;
	}


	bp_private = BIO_new_file(priv_key_path_s, "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
	if(ret != 1){
		free_all();
        return -3;
	}


	bp_public = BIO_new_file(pub_key_path_s, "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
		free_all();
        return -4;
	}

    free_all();

    return 0;
}

int key_pair_generate_ec(char* priv_key_path, char* pub_key_path, char* priv_key_path_s, char* pub_key_path_s){


	int ret = 0;

    EC_KEY* eckey = EC_KEY_new();

    if(eckey == NULL){

        return -10;
    }

    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);


    if(ecgroup == NULL){

        return -11;
    }


    ret = EC_KEY_set_group(eckey, ecgroup);

	if(ret != 1){

        return -12;
	}


    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);



    ret = EC_KEY_generate_key(eckey);

	if(ret != 1){

        return -14;
	}


	bp_private = BIO_new_file(priv_key_path, "w+");

	ret = PEM_write_bio_ECPrivateKey(bp_private, eckey, NULL, NULL, 0, NULL, NULL);
	if(ret != 1){
    
		free_all_ec();
        return -3;
	}

	bp_public = BIO_new_file(pub_key_path, "w+");
	ret = PEM_write_bio_EC_PUBKEY(bp_public, eckey);
	if(ret != 1){
		free_all_ec();
        return -4;
	}

    free(eckey);
    free(ecgroup);
    free_all_ec();


    eckey = EC_KEY_new();

    if(eckey == NULL){

        return -10;
    }

    ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);


    if(ecgroup == NULL){

        return -11;
    }


    ret = EC_KEY_set_group(eckey, ecgroup);

	if(ret != 1){

        return -12;
	}


    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);



    ret = EC_KEY_generate_key(eckey);

	if(ret != 1){

        return -14;
	}


	bp_private = BIO_new_file(priv_key_path_s, "w+");

	ret = PEM_write_bio_ECPrivateKey(bp_private, eckey, NULL, NULL, 0, NULL, NULL);
	if(ret != 1){
    
		free_all_ec();
        return -3;
	}

	bp_public = BIO_new_file(pub_key_path_s, "w+");
	ret = PEM_write_bio_EC_PUBKEY(bp_public, eckey);
	if(ret != 1){
		free_all_ec();
        return -4;
	}

    free(eckey);
    free(ecgroup);
    free_all_ec();


    return 0;
}


int asym_encrypt(char* pub_key_path, char* enc_msg_path, int msg_len, char* msg){

    int result;

    FILE* fp;
    EVP_PKEY* pub_key = NULL;

    char* enc_msg = NULL;

    int enc_len = 0;

    char* err;

    fp = fopen(pub_key_path, "r");

    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);


    RSA* rsa_pub_key = EVP_PKEY_get1_RSA(pub_key);

    enc_msg = (char*)malloc(RSA_size(rsa_pub_key));

    err = (char*)malloc(130 * sizeof(char));

    enc_len = RSA_public_encrypt(
                    msg_len + 1, 
                    (unsigned char*)msg,
                    (unsigned char*)enc_msg,
                    rsa_pub_key,
                    RSA_PKCS1_OAEP_PADDING);



    unsigned char* enc_hex = char2hex(enc_len, (unsigned char*)enc_msg);

    printf("enclen: %d\n", enc_len);

    fp = fopen(enc_msg_path, "w");

    fputs((char*)enc_hex, fp);

    fclose(fp);

    RSA_free(rsa_pub_key);
    EVP_PKEY_free(pub_key);
    free(enc_msg);
    free(err);

    free(enc_hex);

    

    return 0;
}

int asym_decrypt(char* pub_key_path, char* priv_key_path, char* enc_msg_path, char* plain_msg){

    FILE* fp;
    EVP_PKEY* priv_key = NULL;


    char* enc_msg = NULL;

    int enc_len = 0;

    char* dec_msg = NULL;

    int dec_len = 0;

    char* err;

    fp = fopen(priv_key_path, "r");

    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);


    RSA* rsa_priv_key = EVP_PKEY_get1_RSA(priv_key);


    int _max_key_len = RSA_size(rsa_priv_key);

    enc_len = _max_key_len * 2 + 1;

    enc_msg = (char*)malloc(enc_len * sizeof(char));

    fp = fopen(enc_msg_path, "r");

    fgets(enc_msg, enc_len, fp);

    fclose(fp);

    unsigned char* dec_bin = hex2char((unsigned char*)enc_msg);

    dec_msg = (char*)malloc(RSA_size(rsa_priv_key));

    err = (char*)malloc(130 * sizeof(char));

    dec_len = RSA_private_decrypt(
                _max_key_len,
                dec_bin,
                (unsigned char*)dec_msg,
                rsa_priv_key,
                RSA_PKCS1_OAEP_PADDING
                );



    strcpy(plain_msg, dec_msg);

    printf("declen: %d\n", dec_len);

    RSA_free(rsa_priv_key);
    EVP_PKEY_free(priv_key);
    free(enc_msg);
    free(dec_msg);
    free(err);

    free(dec_bin);

    return 0;
}


int asym_shared_keygen_ec(char* key_path, char* pub_key_path, char* peer_pub_key_path, char* skey_path){

    int result;

    FILE* fp;
    EC_KEY* pkey = NULL;
    EC_KEY* pub_key = NULL;

    EC_KEY* peer_pub_key = NULL;
    EC_POINT *peer_pub_point = NULL;

    char* enc_msg = NULL;

    int enc_len = 0;

    char* err;

    fp = fopen(key_path, "r");

    pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen(pub_key_path, "r");

    pub_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen(peer_pub_key_path, "r");

    peer_pub_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    printf("loaded\n");

    peer_pub_point = EC_KEY_get0_public_key(peer_pub_key);

    unsigned char* secret;
    int field_size;
    size_t secret_len = 0;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pkey));
	secret_len = (field_size + 7) / 8;
	secret = OPENSSL_malloc(secret_len);

    secret_len = ECDH_compute_key(secret, secret_len, peer_pub_point, pkey, NULL);

    unsigned char* enc_hex = char2hex(secret_len, secret);

    fp = fopen(skey_path, "w");

    fputs((char*)enc_hex, fp);

    fclose(fp);

    printf("%d\n", secret_len);


    free(enc_hex);



    

    return 0;
}

int asym_shared_keycheck_ec(char* key_path, char* pub_key_path, char* peer_pub_key_path, char* skey_path){


    int result;

    FILE* fp;
    EC_KEY* pkey = NULL;
    EC_KEY* pub_key = NULL;

    EC_KEY* peer_pub_key = NULL;
    EC_POINT *peer_pub_point = NULL;

    char* enc_msg = NULL;

    int enc_len = 0;

    char* err;

    fp = fopen(key_path, "r");

    pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen(pub_key_path, "r");

    pub_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen(peer_pub_key_path, "r");

    peer_pub_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    printf("loaded\n");

    peer_pub_point = EC_KEY_get0_public_key(peer_pub_key);

    unsigned char* secret;
    int field_size;
    size_t secret_len = 0;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pkey));
	secret_len = (field_size + 7) / 8;
	secret = OPENSSL_malloc(secret_len);

    secret_len = ECDH_compute_key(secret, secret_len, peer_pub_point, pkey, NULL);

    printf("secret len: %d\n", secret_len);

    enc_len = secret_len * 2 + 1;

    enc_msg = (char*)malloc(enc_len * sizeof(char));

    fp = fopen(skey_path, "r");

    fgets(enc_msg, enc_len, fp);

    fclose(fp);

    unsigned char* enc = hex2char(enc_msg);

    int cmpres = memcmp(secret, enc, secret_len);

    printf("result: %d (should be zero)\n", cmpres);

    free(enc);


    return 0;
}



int asym_pipe(char* pub_key_path, char* priv_key_path, int msg_len, char* msg){

    int result;

    FILE* fp;
    EVP_PKEY* pub_key = NULL;
    EVP_PKEY* priv_key = NULL;

    char* enc_msg = NULL;

    int enc_len = 0;

    char* dec_msg = NULL;

    int dec_len = 0;

    char* errmsg;

    fp = fopen(pub_key_path, "r");

    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen(priv_key_path, "r");

    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    RSA* rsa_pub_key = EVP_PKEY_get1_RSA(pub_key);

    RSA* rsa_priv_key = EVP_PKEY_get1_RSA(priv_key);

    int _enc_max = RSA_size(rsa_pub_key);

    int _dec_max = RSA_size(rsa_priv_key);

    printf("enc: %d, dec: %d\n", _enc_max, _dec_max);

    enc_msg = (char*)malloc(_enc_max);

    dec_msg = (char*)malloc(_dec_max);

    errmsg = (char*)malloc(130 * sizeof(char));

    enc_len = RSA_public_encrypt(
                    msg_len + 1, 
                    (unsigned char*)msg,
                    (unsigned char*)enc_msg,
                    rsa_pub_key,
                    RSA_PKCS1_OAEP_PADDING);

    printf("done\n");

    unsigned char* enc_hex = char2hex(enc_len, (unsigned char*)enc_msg);
   
    unsigned char* dec_bin = hex2char(enc_hex);

    compare_two_arrays(enc_len, enc_msg, dec_bin);

    dec_len = RSA_private_decrypt(
                enc_len,
                dec_bin,
                (unsigned char*)dec_msg,
                rsa_priv_key,
                RSA_PKCS1_OAEP_PADDING
                );

    printf("%d: %s\n", dec_len, dec_msg);


    RSA_free(rsa_pub_key);
    RSA_free(rsa_priv_key);  
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);
    free(enc_msg);  
    free(dec_msg);
    free(errmsg); 
    free(enc_hex);
    free(dec_bin);
    return 0;
}


void cert_create(){

    time_t exp_ca;
    time(&exp_ca);
    exp_ca += 315360000;

    time_t exp_s;
    time(&exp_s);
    exp_s += 31536000;

    char* serial_ca = "6d530ea7d4a0f7745fea74dc700a2c23d6aca20e";
    char* serial_s = "5f4e186311429e8e08f3d6ff656d7e7233860c67";
    ASN1_INTEGER* serial_asn1 = ASN1_INTEGER_new();
    ASN1_INTEGER* serial_asn1_s = ASN1_INTEGER_new();

    X509* x509_ca = X509_new();
    X509* x509_s = X509_new();

    X509V3_CTX extctx;
    X509_EXTENSION *extension_usage = NULL;
    X509_EXTENSION *extension_skid = NULL;
    X509_EXTENSION *extension_akid = NULL;

    X509V3_set_ctx_nodb(&extctx);

    //X509_NAME* ca_name = X509_NAME_new();
    //X509_NAME* s_name = X509_NAME_new();

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
    akid->keyid = ASN1_OCTET_STRING_new();
    X509_EXTENSION *extakid = NULL;

    X509_EXTENSION *extskid = NULL;
    ASN1_OCTET_STRING *skid = NULL;

    char *subject_alt_name = "DNS:localhost";
    X509_EXTENSION *extension_san = NULL;
    ASN1_OCTET_STRING *subject_alt_name_ASN1 = NULL;
    subject_alt_name_ASN1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(subject_alt_name_ASN1, (unsigned char*) subject_alt_name, strlen(subject_alt_name));
    X509_EXTENSION_create_by_NID(&extension_san, NID_subject_alt_name, 0, subject_alt_name_ASN1);


    FILE* fp = fopen("./ca_priv.pem", "r");

    EVP_PKEY* priv_key_ca = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen("./ca_pub.pem", "r");

    EVP_PKEY* pub_key_ca = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen("./s_priv.pem", "r");

    EVP_PKEY* priv_key_s = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen("./s_pub.pem", "r");

    EVP_PKEY* pub_key_s = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    X509_set_version(x509_ca, 2);

    
    BIGNUM* q = BN_new();

    BN_hex2bn(&q, serial_ca);

    serial_asn1 = BN_to_ASN1_INTEGER(q, serial_asn1);

    X509_set_serialNumber(x509_ca, serial_asn1);
    
    /*
    if(ASN1_INTEGER_set(X509_get_serialNumber(x509_ca), 234) == 0){
        printf("asn1 set serial number fail\n");
    }
    */


    if(X509_time_adj_ex(X509_getm_notBefore(x509_ca), 0, 0, 0) == NULL){
        printf("set time fail\n");
    }

    if(X509_time_adj_ex(X509_getm_notAfter(x509_ca), 0, 0, &exp_ca) == NULL){
        printf("set end time fail\n");
    }

    X509_NAME* ca_name = X509_get_subject_name(x509_ca);
    X509_NAME_add_entry_by_txt(ca_name, "CN" , MBSTRING_ASC, (unsigned char *)"localhost_ca", -1, -1, 0);

    
    if (X509_set_issuer_name(x509_ca, ca_name) != 1){
        printf("set ca name fail\n");
    }


    //set public key
    if(X509_set_pubkey(x509_ca, pub_key_ca) == 0){
        printf("set pubkey fail\n");
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

    //sign certificate with private key
    if(X509_sign(x509_ca, priv_key_ca, EVP_sha256()) == 0){
        printf("sign fail\n");
        printf("Creating certificate failed...\n");
    }

    X509_set_version(x509_s, 2);

    BIGNUM* q_s = BN_new();

    BN_hex2bn(&q_s, serial_s);

    serial_asn1_s = BN_to_ASN1_INTEGER(q_s, serial_asn1_s);

    X509_set_serialNumber(x509_s, serial_asn1_s);

    /*
    if(ASN1_INTEGER_set(X509_get_serialNumber(x509_s), 234) == 0){
        printf("asn1 set serial number fail\n");
    }
    */


    if(X509_time_adj_ex(X509_getm_notBefore(x509_s), 0, 0, 0) == NULL){
        printf("set time fail\n");
    }

    if(X509_time_adj_ex(X509_getm_notAfter(x509_s), 0, 0, &exp_s) == NULL){
        printf("set end time fail\n");
    }

    X509_NAME* s_name = X509_get_subject_name(x509_s);
    X509_NAME_add_entry_by_txt(s_name ,"CN" , MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);


    if(X509_set_issuer_name(x509_s, ca_name) != 1){
        printf("issuer name failed\n");
    }


    //set public key
    if(X509_set_pubkey(x509_s, pub_key_s) == 0){
        printf("set pubkey fail\n");
    }

    X509_pubkey_digest(x509_s, EVP_sha1(), md, &md_len);
    skid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(skid, md, md_len);
    extskid = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid);
    X509_add_ext(x509_s, extskid, -1);

    X509_add_ext(x509_s, extakid, -1);

    X509_add_ext(x509_s, extension_san, -1);


    //sign certificate with private key
    if(X509_sign(x509_s, priv_key_ca, EVP_sha256()) == 0){
        printf("sign fail\n");
        printf("Creating certificate failed...\n");
    }


    fp = fopen("ca.crt.pem", "wb");
    PEM_write_X509(fp, x509_ca);
    fclose(fp);

    fp = fopen("srv.crt.pem", "wb");
    PEM_write_X509(fp, x509_s);
    fclose(fp);

    X509_free(x509_ca);
    X509_free(x509_s);
    EVP_PKEY_free(priv_key_ca);
    EVP_PKEY_free(priv_key_s);
    EVP_PKEY_free(pub_key_ca);
    EVP_PKEY_free(pub_key_s);

}


void cert_verify(){

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 

    BIO* cert = NULL;
    BIO* intermediate = NULL;


    cert = BIO_new(BIO_s_file());

    intermediate = BIO_new(BIO_s_file());

    int ret = BIO_read_filename(cert, "./srv.crt.pem");

    ret = BIO_read_filename(intermediate, "./ca.crt.pem");

    //cert_info(cert);
    //cert_info(intermediate);
    int res = sig_verify(cert,intermediate);
    printf("result: %d\n",res);


    BIO_free_all(cert);
    BIO_free_all(intermediate);


}

void cert_show(){


    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests(); 

    BIO* cert = NULL;
    BIO* intermediate = NULL;


    cert = BIO_new(BIO_s_file());

    intermediate = BIO_new(BIO_s_file());

    int ret = BIO_read_filename(cert, "./srv.crt.pem");

    ret = BIO_read_filename(intermediate, "./ca.crt.pem");

    cert_info(cert);
    cert_info(intermediate);



    BIO_free_all(cert);
    BIO_free_all(intermediate);


}

int sig_verify(BIO* cert_pem, BIO* intermediate_pem)
{
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

void cert_info(BIO* cert_pem)
{
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


void signature(){

    int result;

    FILE* fp;

    EC_KEY* pkey = NULL;
    EC_KEY* pub_key = NULL;

    fp = fopen("./ca_priv.pem", "r");

    pkey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    fp = fopen("./ca_pub.pem", "r");

    pub_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

    fclose(fp);

    // sha256 "hello"
    char* hashstr = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    int hash_length = strlen(hashstr);
    hash_length = hash_length / 2;

    unsigned char* hash = hex2char(hashstr);

	ECDSA_SIG* sig = ECDSA_do_sign(hash, hash_length, pkey);
	if (sig == NULL) {
		printf("signature failed\n");
        return;
	}

    int ret = ECDSA_do_verify(hash, hash_length, sig, pub_key);
    
    printf("result: %d\n", ret);

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

}

static void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "  %s:%d: %s\n", label, length, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    print_cn_name("issueer cn: ", iname);

    print_cn_name("subject cn: ", sname);

    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    
    if(preverify == 0)
    {


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

void tls(){

    int dtls_flag = 0;
    OSSL_LIB_CTX *libctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CTX *serverctx = NULL, *clientctx = NULL;

    char *certfile_ca = "ca.crt.pem";
    char *certfile = "srv.crt.pem";
    char *privkeyfile = "s_priv.pem";

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

/*
    if (!SSL_CTX_use_certificate_file(clientctx, certfile_c, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_use_PrivateKey_file(clientctx, privkeyfile_c, SSL_FILETYPE_PEM))
        goto err;

    if (!SSL_CTX_check_private_key(clientctx))
        goto err;

*/
    
    printf("client file done: %s\n", certfile_ca);

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

    create_tls_client(clientssl);


err:

    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(serverctx);
    SSL_CTX_free(clientctx);
    OSSL_LIB_CTX_free(libctx);
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

        printf("%d: %c%c %d %x ", i, hexarray[2 * i], hexarray[2 * i + 1], n, chararray[i]);

    }

    printf("\n");

    return chararray;
}


void compare_two_arrays(int len, char* arr1, char* arr2){


    for(int i = 0 ; i < len; i++){


        if(arr1[i] != arr2[i]){
            
            printf("not equal at: %d, %x %x\n", i, arr1[i], arr2[i]);

        }


    }



}



void free_all(){


	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);


}

void free_all_ec(){


	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	
	


}