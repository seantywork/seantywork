
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/internal/aead.h>
#include <linux/scatterlist.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/ip.h>

#define MAX_MSG_LEN 128
#define GCM_ASSOCLEN 16
#define GCM_TAGLEN 16
#define GCM_NONCE_SALTLEN 4
#define GCM_NONCE_BODYLEN 8
#define GCM_NONCELEN GCM_NONCE_SALTLEN + GCM_NONCE_BODYLEN
#define GCM_KEY_BODYLEN 32
#define GCM_KEY_SALTLEN 4
#define GCM_KEYLEN GCM_KEY_BODYLEN + GCM_KEY_SALTLEN

static int run_kcrypt(void) {
    char print_messge[MAX_MSG_LEN] = {0};
    char *test_data = "this is test data for kcrypt";
    int test_datalen = 0;
    int aes_gcm_assoclen = GCM_ASSOCLEN;
    int aes_gcm_taglen = GCM_TAGLEN;
    int nonce_saltlen = GCM_NONCE_SALTLEN;
    size_t buffer_size = MAX_MSG_LEN;

    struct crypto_aead *tfm = NULL;
    struct aead_request *req = NULL;
    u8 *buffer = NULL;
    u8 *buffer2 = NULL;
    u8 *bp = NULL, *bp_end = NULL, *bp_print = NULL;
    struct scatterlist sg = { 0 };
    struct scatterlist sg2 = { 0 };
    DECLARE_CRYPTO_WAIT(wait);
    test_datalen = strlen(test_data);

    u8 assoc_msg[GCM_ASSOCLEN] = { 
        0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44,
    };
    u8 nonce[GCM_NONCELEN] = { 
        0x99, 0x99, 0x99, 0x99,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 key[GCM_KEYLEN] = { 
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 
        0x00, 0x00, 0x00, 0x00,
    }; 

    int err = -1;

    tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0, 0);

    // tfm = crypto_alloc_aead("gcm(aes)", 0, 0);

    if (IS_ERR(tfm)) {
        err = PTR_ERR(tfm);
        printk("kcrypt: alloc aead: %d.\n", err);
        goto kcrypt_end;
    }

    err = crypto_aead_setauthsize(tfm, aes_gcm_taglen);
    if (err != 0) {
        printk("kcrypt: set authsize %d.\n", err);
        goto kcrypt_end;
    }

    memcpy(key + GCM_KEY_BODYLEN, nonce, nonce_saltlen);
    get_random_bytes(nonce + nonce_saltlen, GCM_NONCE_BODYLEN);
    err = crypto_aead_setkey(tfm, key, GCM_KEYLEN);
    if (err != 0) {
        printk("kcrypt: set key failed: %d.\n", err);
        goto kcrypt_end;
    }

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (req == NULL) {
        err = -ENOMEM;
        printk("kcrypt: request alloc failed\n");
        goto kcrypt_end;
    }


    buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (buffer == NULL) {
        err = -ENOMEM;
        printk("kcrypt: buffer alloc failed \n");
        goto kcrypt_end;
    }

    buffer2 = kmalloc(buffer_size, GFP_KERNEL);
    if (buffer2 == NULL) {
        err = -ENOMEM;
        printk("kcrypt: buffer alloc failed \n");
        goto kcrypt_end;
    }
    
    memcpy(buffer, assoc_msg, aes_gcm_assoclen);
    memcpy(buffer + aes_gcm_assoclen, test_data, test_datalen);
    bp = buffer + aes_gcm_assoclen;
    bp_end = bp + test_datalen;

    memset(print_messge, 0, MAX_MSG_LEN);
    bp_print = print_messge;
    while (bp != bp_end) {
        *bp_print =  isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("original data: %s\n", print_messge);
    bp_print = NULL;
    memset(print_messge, 0, MAX_MSG_LEN);

    sg_init_one(&sg, buffer, buffer_size);
    sg_init_one(&sg2, buffer2, buffer_size);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                   CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);


    aead_request_set_crypt(req, &sg, &sg2, test_datalen, nonce + nonce_saltlen);
    aead_request_set_ad(req, aes_gcm_assoclen);

    err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: encrypt: failed: %d.\n", err);
        goto kcrypt_end;
    }
    
    printk("kcrypt: encryption completed\n");

    bp_print = print_messge;
    memcpy(buffer2, assoc_msg, aes_gcm_assoclen);
    bp = buffer2;
    bp_end = bp + aes_gcm_assoclen;
    while (bp != bp_end) {
        *bp_print = isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }

    printk("  - assoc: %s\n", print_messge);
    bp_print = NULL;
    memset(print_messge, 0, MAX_MSG_LEN);

    bp_print = print_messge;
    bp_end += test_datalen;
    while (bp != bp_end) {
        *bp_print = isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("  - cryptogram: %s\n", print_messge);
    bp_print = NULL;
    memset(print_messge, 0, MAX_MSG_LEN);

    bp_print = print_messge;
    bp_end += aes_gcm_taglen;
    while (bp != bp_end) {
        *bp_print = isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("  - auth tag: %s\n", print_messge);
    bp_print = NULL;
    memset(print_messge, 0, MAX_MSG_LEN);

    aead_request_set_crypt(req, &sg2, &sg, test_datalen + aes_gcm_taglen, nonce + nonce_saltlen);
    aead_request_set_ad(req, aes_gcm_taglen);

    err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: decrypt: %d\n", err);
        goto kcrypt_end;
    }
    printk("kcrypt: decryption completed\n");

    bp_print = print_messge;
    bp = buffer + aes_gcm_assoclen;
    bp_end = bp + test_datalen;
    while (bp != bp_end) {
        *bp_print = isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("authenticated plaintext: %s\n", print_messge);

kcrypt_end:

    if (req != NULL) {
        aead_request_free(req);
    }

    if (tfm != NULL) {
        crypto_free_aead(tfm);
    }

    if (buffer != NULL) {
        kfree(buffer);
    }

    if (buffer2 != NULL) {
        kfree(buffer2);
    }

    return err;
}


static int __init init_kcrypt(void) {
    printk("init kcrypt\n");
    return run_kcrypt();
}

static void __exit exit_kcrypt(void) {
    printk("exit kcrypt\n");
}

module_init(init_kcrypt);
module_exit(exit_kcrypt);

MODULE_LICENSE("GPL");