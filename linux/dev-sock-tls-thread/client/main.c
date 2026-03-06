
#include "client.h"

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

#if 0
const char* const PREFERRED_CIPHERS = "kEECDH:kEDH:kRSA:AESGCM:AES256:AES128:3DES:SHA256:SHA84:SHA1:!aNULL:!eNULL:!EXP:!LOW:!MEDIUM!ADH:!AECDH";
#endif

#if 0
const char* const PREFERRED_CIPHERS = NULL;
#endif

#if 0
const char* PREFERRED_CIPHERS =

/* TLS 1.2 only */
"ECDHE-ECDSA-AES256-GCM-SHA384:"
"ECDHE-RSA-AES256-GCM-SHA384:"
"ECDHE-ECDSA-AES128-GCM-SHA256:"
"ECDHE-RSA-AES128-GCM-SHA256:"

/* TLS 1.2 only */
"DHE-DSS-AES256-GCM-SHA384:"
"DHE-RSA-AES256-GCM-SHA384:"
"DHE-DSS-AES128-GCM-SHA256:"
"DHE-RSA-AES128-GCM-SHA256:"

/* TLS 1.0 only */
"DHE-DSS-AES256-SHA:"
"DHE-RSA-AES256-SHA:"
"DHE-DSS-AES128-SHA:"
"DHE-RSA-AES128-SHA:"

/* SSL 3.0 and TLS 1.0 */
"EDH-DSS-DES-CBC3-SHA:"
"EDH-RSA-DES-CBC3-SHA:"
"DH-DSS-DES-CBC3-SHA:"
"DH-RSA-DES-CBC3-SHA";
#endif

int main(int argc, char* argv[])
{
    UNUSED(argc); UNUSED(argv);
    

    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;
    
    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    
    do {
        
        init_openssl_library();
        

        const SSL_METHOD* method = SSLv23_method();
        ssl_err = ERR_get_error();
        
        ASSERT(NULL != method);
        if(!(NULL != method))
        {
            print_error_string(ssl_err, "SSLv23_method");
            break; /* failed */
        }
        
        ctx = SSL_CTX_new(method);

        ssl_err = ERR_get_error();
        
        ASSERT(ctx != NULL);
        if(!(ctx != NULL))
        {
            print_error_string(ssl_err, "SSL_CTX_new");
            break; /* failed */
        }
        

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

        SSL_CTX_set_verify_depth(ctx, 5);


        

        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        long old_opts = SSL_CTX_set_options(ctx, flags);
        UNUSED(old_opts);
        

        res = SSL_CTX_load_verify_locations(ctx, VERIFICATION_LOCATION, NULL);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
 
            print_error_string(ssl_err, "SSL_CTX_load_verify_locations");
            break; /* failed */
        }
        

        web = BIO_new_ssl_connect(ctx);
        ssl_err = ERR_get_error();
        
        ASSERT(web != NULL);
        if(!(web != NULL))
        {
            print_error_string(ssl_err, "BIO_new_ssl_connect");
            break; /* failed */
        }
        

        res = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "BIO_set_conn_hostname");
            break; /* failed */
        }
        

        BIO_get_ssl(web, &ssl);
        ssl_err = ERR_get_error();
        
        ASSERT(ssl != NULL);
        if(!(ssl != NULL))
        {
            print_error_string(ssl_err, "BIO_get_ssl");
            break; /* failed */
        }
        


        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "SSL_set_cipher_list");
            break; 
        }


        res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {

            print_error_string(ssl_err, "SSL_set_tlsext_host_name");
            break;
        }
        
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
        ssl_err = ERR_get_error();
        
        ASSERT(NULL != out);
        if(!(NULL != out))
        {
            print_error_string(ssl_err, "BIO_new_fp");
            break; /* failed */
        }
        


        res = BIO_do_connect_retry(web, 5, 100);
        ssl_err = ERR_get_error();
        


        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "BIO_do_connect_retry");
            break; /* failed */
        }

        
        X509* cert = SSL_get_peer_certificate(ssl);
        if(cert) { X509_free(cert); } 
        
        ASSERT(NULL != cert);
        if(NULL == cert)
        {
  
            print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
            break; /* failed */
        }

        res = SSL_get_verify_result(ssl);
        
        ASSERT(X509_V_OK == res);
        if(!(X509_V_OK == res))
        {

            print_error_string((unsigned long)res, "SSL_get_verify_results");
            break; /* failed */
        }
        
        
        // BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\nHost: " HOST_NAME "\r\nConnection: close\r\n\r\n");
        // BIO_puts(out, "\nFetching: " HOST_RESOURCE "\n\n");
        
        int len = 0;
        do {
            char buff[1024] = {0};
            char rbuff[1024] = {0};
            size_t rlen = 0;
            size_t wlen = 0;
            int timeout = 0;

            int ms_until_deadline;

            long timeout_limit = 3000;


            printf("client message : ");
            

            fgets(buff, 1024, stdin);

            BIO_write_ex(web, buff, sizeof(buff), &wlen);

            struct timespec wnow;

            clock_gettime(CLOCK_MONOTONIC_RAW, &wnow);

            struct timespec wdeadline ;

            while(BIO_should_retry(web)){

                clock_gettime(CLOCK_MONOTONIC_RAW, &wdeadline);

                ms_until_deadline = ((wdeadline.tv_sec - wnow.tv_sec) * 1000 + (wdeadline.tv_nsec - wnow.tv_nsec) / 1000000);
                
                printf("%d\n", ms_until_deadline);

                
                if(ms_until_deadline > timeout_limit){
                    timeout = 1;
                    break;
                }

                BIO_write_ex(web, buff, sizeof(buff), &wlen);

            }

            if(timeout == 1){
                printf("write timeout\n");
                timeout = 0;
            }

            ms_until_deadline = 0;


            BIO_read_ex(web, rbuff, sizeof(rbuff), &rlen);

            struct timespec rnow;

            clock_gettime(CLOCK_MONOTONIC_RAW, &rnow);

            struct timespec rdeadline;

            while(BIO_should_retry(web)){

                clock_gettime(CLOCK_MONOTONIC_RAW, &rdeadline);

                ms_until_deadline = ((rdeadline.tv_sec - rnow.tv_sec) * 1000 + (rdeadline.tv_nsec - rnow.tv_nsec) / 1000000);

                
                if(ms_until_deadline > timeout_limit){
                    timeout = 1;
                    break;
                }


                BIO_read_ex(web, rbuff, sizeof(buff), &rlen);

            }

            if(timeout == 1){
                printf("read timeout\n");
                timeout = 0;
            } else {
                printf("%s\n",rbuff);
            }

            
            
            
        } while (1);
        
        printf("client terminated\n");

        ret = 0;
        
    } while (0);
    
    if(out)
        BIO_free(out);
    
    if(web != NULL)
        BIO_free_all(web);
    
    if(NULL != ctx)
        SSL_CTX_free(ctx);
    
    return ret;
}

void init_openssl_library(void)
{

    (void)SSL_library_init();

    
    SSL_load_error_strings();

    CONF_modules_load(NULL, NULL, CONF_MFLAGS_IGNORE_MISSING_FILE);

#if defined (OPENSSL_THREADS)
    /* https://www.openssl.org/docs/crypto/threads.html */
    fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

void print_cn_name(const char* label, X509_NAME* const name)
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
        
        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    
    do
    {
        if(!cert) break; /* failed */
        
        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        
        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }
                

                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }
                
                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);
    
    if(names)
        GENERAL_NAMES_free(names);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
    
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    

    print_cn_name("Issuer (cn)", iname);
    

    print_cn_name("Subject (cn)", sname);
    
    if(depth == 0) {

        print_san_name("Subject (san)", cert);
    }
    
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

#if !defined(NDEBUG)
    return 1;
#else
    return preverify;
#endif
}

void print_error_string(unsigned long err, const char* const label)
{
    const char* const str = ERR_reason_error_string(err);
    if(str)
        fprintf(stderr, "%s\n", str);
    else
        fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}
