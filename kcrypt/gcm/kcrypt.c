
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/internal/aead.h>
#include <linux/scatterlist.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/ip.h>






static int run_kcrypt(void) {


    char *test_data = "this is test data for kcrypt";
    int test_datalen = 0;
    int aes_gcm_assoclen = 16;
    int aes_gcm_taglen = 16;
    int nonce_saltlen = 4;
    test_datalen = strlen(test_data);

    struct crypto_aead *tfm = NULL;
    struct aead_request *req = NULL;
    u8 *buffer = NULL;
    u8 *buffer2 = NULL;
    size_t buffer_size = 1024;
    u8 *bp = NULL, *bp_end = NULL;
    struct scatterlist sg = { 0 };
    struct scatterlist sg2 = { 0 };
    DECLARE_CRYPTO_WAIT(wait);

    u8 assoc_msg[16] = { 
        0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44,
    };
    u8 nonce[12] = { 
        0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 key[36] = { 
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 
        0xcc, 0xdd, 0xee, 0xff,
    }; 
/*
    u8 key[36] = { 
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb,
    }; 
*/
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

    get_random_bytes(nonce + 4, 8);
    err = crypto_aead_setkey(tfm, key, 36);
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

    printk("original data: ");
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }


    sg_init_one(&sg, buffer, buffer_size);
    sg_init_one(&sg2, buffer2, buffer_size);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                   CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);


    aead_request_set_crypt(req, &sg, &sg2, test_datalen, nonce + nonce_saltlen);
    aead_request_set_ad(req, aes_gcm_assoclen);

    // aead_request_set_ad(req, 0);

    err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: encrypt: failed: %d.\n", err);
        goto kcrypt_end;
    }
    memcpy(buffer2, assoc_msg, aes_gcm_assoclen);
    printk("assoc: ");
    bp = buffer2;
    bp_end = bp + aes_gcm_assoclen;
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    printk("cryptogram: ");
    bp_end += test_datalen;
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    printk("authentication tag: ");
    bp_end += aes_gcm_taglen;
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    aead_request_set_crypt(req, &sg2, &sg, test_datalen + aes_gcm_taglen, nonce + nonce_saltlen);
    aead_request_set_ad(req, aes_gcm_taglen);

    /*
    err = crypto_aead_setkey(tfm, key, 36);
    if (err != 0) {
        printk("kcrypt: setkey again: %d.\n", err);
        goto kcrypt_end;
    }
    */

    err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: decrypt: %d\n", err);
        goto kcrypt_end;
    }


    printk("authenticated plaintext: ");
    bp = buffer + aes_gcm_assoclen;
    bp_end = bp + test_datalen;
 
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }


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