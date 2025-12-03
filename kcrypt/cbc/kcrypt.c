
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <crypto/hash.h>
#include <crypto/hmac.h>



static int hmac_sha256(unsigned char *key, size_t key_size, unsigned char *ikm, size_t ikm_len, unsigned char *okm, size_t okm_len){
	struct crypto_shash *tfm;
	struct shash_desc *shash;
	int ret = -1;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		printk("hmac: crypto_alloc_shash failed\n");
		return -1;
	}

	ret = crypto_shash_setkey(tfm, key, key_size);
	if (ret) {
		printk("hmac: crypto_ahash_setkey failed: %d", ret);
		goto failed;
	}

	shash = kzalloc(sizeof(*shash) + crypto_shash_descsize(tfm),GFP_KERNEL);
	if (!shash) {
		ret = -ENOMEM;
		printk("hmac: zalloc: %d\n", ret);
		goto failed;
	}

	shash->tfm = tfm;

	ret = crypto_shash_digest(shash, ikm, ikm_len, okm);

	kfree(shash);

failed:
	crypto_free_shash(tfm);
	return ret;


}


static int run_kcrypt(void) {


    char *test_data = "this is test data for kcrypt";
    int test_datalen = 0;
    int test_datapaddedlen = 0;
    int aes_blocklen = 16;
    int aes_cbc_noncelen = 16;
    int aes_cbc_authtrunclen = 32;
    int padtest = 0;
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    u8 *buffer = NULL;
    u8 *buffer2 = NULL;
    size_t buffer_size = 1024;
    u8 *bp = NULL, *bp_end = NULL;
    struct scatterlist sg = { 0 };
    struct scatterlist sg2 = { 0 };
    DECLARE_CRYPTO_WAIT(wait);
    test_datalen = strlen(test_data);
    padtest = test_datalen % aes_blocklen;
    if(padtest != 0){
        test_datapaddedlen = test_datalen + (aes_blocklen - padtest);
    }

    u8 nonce[16] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 nonce_org[16] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 key[32] = { 
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 
    }; 
    u8 auth_key[32] = { 
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22,
    }; 
    u8 auth_val[32] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 auth_val_org[32] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    int err = -1;

    printk("kcrypt: datalen: %d\n", test_datalen);
    printk("kcrypt: padded datalen: %d\n", test_datapaddedlen);

    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);

    if (IS_ERR(tfm)) {
        err = PTR_ERR(tfm);
        printk("kcrypt: alloc skcipher: %d.\n", err);
        goto kcrypt_end;
    }
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (req == NULL) {
        err = -ENOMEM;
        printk("kcrypt: request alloc failed\n");
        goto kcrypt_end;
    }
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);

    err = crypto_skcipher_setkey(tfm, key, 32);
    if (err != 0) {
        printk("kcrypt: set key failed: %d.\n", err);
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
    memset(buffer, 0, buffer_size);
    memset(buffer2, 0, buffer_size);
    get_random_bytes(nonce, aes_cbc_noncelen);
    memcpy(nonce_org, nonce, aes_cbc_noncelen);
    sg_init_one(&sg, buffer, buffer_size);
    sg_init_one(&sg2, buffer2, buffer_size);
    memcpy(buffer, nonce, aes_cbc_noncelen);
    memcpy(buffer + aes_cbc_noncelen, test_data, test_datalen);
    err = hmac_sha256(auth_key, 32, buffer, aes_cbc_noncelen + test_datapaddedlen, auth_val, aes_cbc_authtrunclen);
    if(err != 0){
        printk("kxfrm: hmac failed: %d\n", err);
        goto kcrypt_end;
    }
    memcpy(auth_val_org, auth_val, aes_cbc_authtrunclen);
    memset(buffer, 0, buffer_size);
    memcpy(buffer, test_data, test_datalen);
    bp = buffer;
    bp_end = bp + test_datapaddedlen;
    printk("original data: ");
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    skcipher_request_set_crypt(req, &sg, &sg2, test_datapaddedlen, nonce);
    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: encrypt: failed: %d.\n", err);
        goto kcrypt_end;
    }

    printk("cryptogram: ");

    bp = buffer2;
    bp_end = bp + test_datapaddedlen;
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    memcpy(nonce, nonce_org, aes_cbc_noncelen);

    skcipher_request_set_crypt(req, &sg2, &sg, test_datapaddedlen, nonce);

    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: decrypt: %d\n", err);
        goto kcrypt_end;
    }
    memcpy(nonce, nonce_org, aes_cbc_noncelen);
    memcpy(buffer2, buffer, buffer_size);
    memset(buffer, 0, buffer_size);
    memcpy(buffer + aes_cbc_noncelen, buffer2, test_datapaddedlen);
    memcpy(buffer, nonce, aes_cbc_noncelen);
    err = hmac_sha256(auth_key, 32, buffer, aes_cbc_noncelen + test_datapaddedlen, auth_val, aes_cbc_authtrunclen);
    if(err != 0){
        printk("kxfrm: hmac failed: %d\n", err);
        goto kcrypt_end;
    }

    printk("authenticated plaintext: ");
    bp = buffer + aes_cbc_noncelen;
    bp_end = bp + test_datapaddedlen;
 
    while (bp != bp_end) {
        printk("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    
    int cmpres = memcmp(auth_val, auth_val_org, sizeof(u8) * aes_cbc_noncelen);
    if(cmpres != 0){
        printk("auth value not matched: %d\n", cmpres);
    } else {
        printk("auth value matched\n");
    }
    



kcrypt_end:

    if (req != NULL) {
        skcipher_request_free(req);
    }

    if (tfm != NULL) {
        crypto_free_skcipher(tfm);
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