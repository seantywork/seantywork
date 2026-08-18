
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

#define MAX_MSG_LEN 128
#define AES_BLOCKLEN 16
#define CBC_IVLEN 16
#define CBC_KEYLEN 32
#define CBC_AUTHKEYLEN 32
#define CBC_AUTHLEN 32

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

    char print_message[MAX_MSG_LEN] = {0};
    char *test_data = "this is test data for kcrypt";
    int test_datalen = 0;
    int test_datapaddedlen = 0;
    int aes_blocklen = AES_BLOCKLEN;
    int aes_cbc_noncelen = CBC_IVLEN;
    int aes_cbc_authlen = CBC_AUTHLEN;
    size_t buffer_size = MAX_MSG_LEN;
    int padtest = 0;
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    u8 *buffer = NULL;
    u8 *buffer2 = NULL;
    u8 *bp = NULL, *bp_end = NULL, *bp_print = NULL;
    struct scatterlist sg = { 0 };
    struct scatterlist sg2 = { 0 };
    DECLARE_CRYPTO_WAIT(wait);
    test_datalen = strlen(test_data);
    padtest = test_datalen % aes_blocklen;
    if(padtest != 0){
        test_datapaddedlen = test_datalen + (aes_blocklen - padtest);
    }

    u8 nonce[CBC_IVLEN] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 nonce_org[CBC_IVLEN] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 key[CBC_KEYLEN] = { 
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 
    }; 
    u8 auth_key[CBC_AUTHKEYLEN] = { 
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x11, 0x22,
    }; 
    u8 auth_val[CBC_AUTHLEN] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    u8 auth_val_org[CBC_AUTHLEN] = { 
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

    err = crypto_skcipher_setkey(tfm, key, CBC_KEYLEN);
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

    err = hmac_sha256(auth_key, CBC_AUTHKEYLEN, buffer, aes_cbc_noncelen + test_datapaddedlen, auth_val, aes_cbc_authlen);
    if(err != 0){
        printk("kcrypt: hmac failed: %d\n", err);
        goto kcrypt_end;
    }

    printk("kcrypt: auth val calculated for nonce + padded data\n");

    memcpy(auth_val_org, auth_val, aes_cbc_authlen);
    memset(buffer, 0, buffer_size);
    memcpy(buffer, test_data, test_datalen);

    memset(print_message, 0, MAX_MSG_LEN);
    bp_print = print_message;
    bp = auth_val_org;
    bp_end = bp + aes_cbc_authlen;
    while (bp != bp_end) {
        *bp_print =  isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("  - auth val: %s\n", print_message);
    bp_print = NULL;
    memset(print_message, 0, MAX_MSG_LEN);

    bp_print = print_message;
    bp = buffer;
    bp_end = bp + test_datalen;

    while (bp != bp_end) {
        *bp_print =  isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("original data: %s\n", print_message);
    bp_print = NULL;
    memset(print_message, 0, MAX_MSG_LEN);

    skcipher_request_set_crypt(req, &sg, &sg2, test_datapaddedlen, nonce);
    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: encrypt: failed: %d.\n", err);
        goto kcrypt_end;
    }

    printk("kcrypt: encryption completed\n");

    bp_print = print_message;
    bp = buffer2;
    bp_end = bp + test_datapaddedlen;
    while (bp != bp_end) {
        *bp_print =  isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("  - cryptogram: %s\n", print_message);
    bp_print = NULL;
    memset(print_message, 0, MAX_MSG_LEN);

    memcpy(nonce, nonce_org, aes_cbc_noncelen);

    skcipher_request_set_crypt(req, &sg2, &sg, test_datapaddedlen, nonce);

    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    if (err != 0) {
        printk("kcrypt: decrypt: %d\n", err);
        goto kcrypt_end;
    }

    printk("kcrypt: decryption completed\n");

    memcpy(nonce, nonce_org, aes_cbc_noncelen);
    memcpy(buffer2, buffer, buffer_size);
    memset(buffer, 0, buffer_size);
    memcpy(buffer, nonce, aes_cbc_noncelen);
    memcpy(buffer + aes_cbc_noncelen, buffer2, test_datapaddedlen);
    err = hmac_sha256(auth_key, CBC_AUTHKEYLEN, buffer, aes_cbc_noncelen + test_datapaddedlen, auth_val, aes_cbc_authlen);
    if(err != 0){
        printk("kcrypt: hmac failed: %d\n", err);
        goto kcrypt_end;
    }

    printk("kcrypt: auth val calculated for nonce + padded data after decryption\n");
    memset(print_message, 0, MAX_MSG_LEN);
    bp_print = print_message;
    bp = auth_val;
    bp_end = bp + aes_cbc_authlen;
    while (bp != bp_end) {
        *bp_print =  isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }
    printk("  - auth val: %s\n", print_message);
    bp_print = NULL;
    memset(print_message, 0, MAX_MSG_LEN);

    int cmpres = memcmp(auth_val, auth_val_org, aes_cbc_noncelen);
    if(cmpres != 0){
        printk("kcrypt: auth value not matched: %d\n", cmpres);
        goto kcrypt_end;
    } else {
        printk("kcrypt: auth value matched\n");
    }
    
    bp_print = print_message;
    bp = buffer + aes_cbc_noncelen;
    bp_end = bp + test_datalen;
 
    while (bp != bp_end) {
        *bp_print =  isprint(*bp) ? *bp : '.';
        bp++;
        bp_print++;
    }

    printk("authenticated plaintext: %s\n", print_message);


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