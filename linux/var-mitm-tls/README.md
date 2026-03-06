# 01 

```shell

./setup.sh

```

# 02


```shell

----------------------------------------------------
|                                                  |      
|                 hacker's router                  | 
|                                                  |
|  -----------------          ----------------     |
|  |   vet11       |          |  veth21      |     |
|  | 192.168.62.5  |          | 192.168.64.5 |     |
|  |    mitm'd 😈  |          |              |     |
----------------------------------------------------
         |                           |
         |                           |
         |                           |
  -----------------           ----------------
  |   veth12      |           |  veth22      |
  |  192.168.62.6 |           | 192.168.64.6 |
  |    client     |           |  server      |
  -----------------           ----------------



```

# 03

```shell

./certs.sh

```

# 04

```shell
sudo ip netns exec net2 openssl s_server -port 9999  -cert ./certs/server.pem -key ./certs/server_priv.pem -cipher AES256-SHA256:@SECLEVEL=0 -tls1_2

```


```shell

sudo ip netns exec net1 openssl s_client -connect 192.168.64.6:9999 -CAfile ./certs/ca.pem -cipher AES256-SHA256:@SECLEVEL=0 -tls1_2
```

# 05

```shell
...
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : AES256-SHA256
...
```

# 06

```c

int hijack_key();


```

# 07

```c
    int dec_len = RSA_private_decrypt(
                data_len,
                (unsigned char*)premaster_raw,
                dec_msg,
                rsa_priv_key,
                RSA_PKCS1_PADDING
                );


```


# 08

```shell
# https://datatracker.ietf.org/doc/html/rfc5246

...
  To generate the key material, compute

      key_block = PRF(SecurityParameters.master_secret,
                      "key expansion",
                      SecurityParameters.server_random +
                      SecurityParameters.client_random);

   until enough output has been generated.  Then, the key_block is
   partitioned as follows:

      client_write_MAC_key[SecurityParameters.mac_key_length]
      server_write_MAC_key[SecurityParameters.mac_key_length]
      client_write_key[SecurityParameters.enc_key_length]
      server_write_key[SecurityParameters.enc_key_length]
      client_write_IV[SecurityParameters.fixed_iv_length]
      server_write_IV[SecurityParameters.fixed_iv_length]

...


```

# 09

```c
/*
 *  steal start
 *  https://github.com/openssl/openssl/blob/master/providers/implementations/kdfs/tls1_prf.c
 *
*/
static int tls1_prf_P_hash(EVP_MAC_CTX *ctx_init,
                           const unsigned char *sec, size_t sec_len,
                           const unsigned char *seed, size_t seed_len,
                           unsigned char *out, size_t olen)
{
    size_t chunk;
    EVP_MAC_CTX *ctx = NULL, *ctx_Ai = NULL;
    unsigned char Ai[EVP_MAX_MD_SIZE];
    size_t Ai_len;
    int ret = 0;

    if (!EVP_MAC_init(ctx_init, sec, sec_len, NULL))
        goto err;
    chunk = EVP_MAC_CTX_get_mac_size(ctx_init);
    if (chunk == 0)
        goto err;
    /* A(0) = seed */
    ctx_Ai = EVP_MAC_CTX_dup(ctx_init);
    if (ctx_Ai == NULL)
        goto err;
    if (seed != NULL && !EVP_MAC_update(ctx_Ai, seed, seed_len))
        goto err;

    for (;;) {
        /* calc: A(i) = HMAC_<hash>(secret, A(i-1)) */
        if (!EVP_MAC_final(ctx_Ai, Ai, &Ai_len, sizeof(Ai)))
            goto err;
        EVP_MAC_CTX_free(ctx_Ai);
        ctx_Ai = NULL;

        /* calc next chunk: HMAC_<hash>(secret, A(i) + seed) */
        ctx = EVP_MAC_CTX_dup(ctx_init);
        if (ctx == NULL)
            goto err;
        if (!EVP_MAC_update(ctx, Ai, Ai_len))
            goto err;
        /* save state for calculating next A(i) value */
        if (olen > chunk) {
            ctx_Ai = EVP_MAC_CTX_dup(ctx);
            if (ctx_Ai == NULL)
                goto err;
        }
        if (seed != NULL && !EVP_MAC_update(ctx, seed, seed_len))
            goto err;
        if (olen <= chunk) {
            /* last chunk - use Ai as temp bounce buffer */
            if (!EVP_MAC_final(ctx, Ai, &Ai_len, sizeof(Ai)))
                goto err;
            memcpy(out, Ai, olen);
            break;
        }
        if (!EVP_MAC_final(ctx, out, NULL, olen))
            goto err;
        EVP_MAC_CTX_free(ctx);
        ctx = NULL;
        out += chunk;
        olen -= chunk;
    }
    ret = 1;

 err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(ctx_Ai);
    OPENSSL_cleanse(Ai, sizeof(Ai));
    return ret;
}
/*
 * steal end
*/
```

# 10

```shell

seclen: 48, seedlen: 54, olen: 48
sec:
0303C50E21125FEC8635A168DA82BD7269D18B1AD4D5BEA6818527F55F4C2872AD6E4EBACA83BAC3B36E69E4ED15916F
seedstr: extended master secretW�SPeK^"�勘�0�U�n^��/��@&r�
seed:
657874656E646564206D61737465722073656372657457E5535065064B1F5E2286E58B981EE730E055C96E5EBA0FFA2FB3D0402672D7
out:
4D35748B193F886FB3193298D08159AE1E94CF77887A2083D6AA164D4E78D734772906F96F336BE5518AF5B6F450EC5A
seclen: 48, seedlen: 77, olen: 160
sec:
4D35748B193F886FB3193298D08159AE1E94CF77887A2083D6AA164D4E78D734772906F96F336BE5518AF5B6F450EC5A
seedstr: key expansion���n_     'B��C񚌠e&Oqb�
}Oɉ�_H�
seed:
6B657920657870616E73696F6EB519C2E76E5F09274282CC43F19A8CA065264F716216D20A7D4FC98907FD5F48840800745893FFE3F025D356EBA71346456907FAB463E830A91CFF28EACF6268
out:
ABAD28DAB7B616EB03B55B58E516B9B6A30FBF6283BE3372179C036F5A662D6CA86CAB7F0C17F5AA6C3FFAB275CA475834F024E6143E1B5AED0A58C720A35E9C7E8EC02569BFCCEECF6E7C5E6DA04008BD98803D346317D9D283C2B7BAB56CED237D9845D9C2B963A9D03FC8A39042A5398E9F15D280B8536485DB2093F5296FF5134EAE36A5B49C096A7C6D210A30EDBA2E61D143B965E6B4664C1E3F821EBD
seclen: 48, seedlen: 47, olen: 12
sec:
4D35748B193F886FB3193298D08159AE1E94CF77887A2083D6AA164D4E78D734772906F96F336BE5518AF5B6F450EC5A
seedstr: client finishedW�SPeK^"�勘�0�U�n^��/��@&r�
seed:
636C69656E742066696E697368656457E5535065064B1F5E2286E58B981EE730E055C96E5EBA0FFA2FB3D0402672D7
out:
B16679F75903CDDED98F1410
seclen: 48, seedlen: 47, olen: 12
sec:
4D35748B193F886FB3193298D08159AE1E94CF77887A2083D6AA164D4E78D734772906F96F336BE5518AF5B6F450EC5A
seedstr: server finished}g��+[��˶�
seed:
7365727665722066696E69736865647D67F8AA2B5B1799B3CBB6E3A700F587A8920B80D7E1848346DF829D5ADD4FE1
out:
9EFC18B4D2A28F38DC3818B6

```

# 11
```shell
# https://datatracker.ietf.org/doc/html/rfc7627
...
The "session_hash" is intended to encompass all relevant session
   information, including ciphersuite negotiation, key exchange
   messages, and client and server identities.  The hash is needed to
   compute the extended master secret and hence must be available before
   the Finished messages.

   This document sets the "session_hash" to cover all handshake messages
   up to and including the ClientKeyExchange.
...
```


# 12

```shell
# https://datatracker.ietf.org/doc/html/rfc7366
...
3.  Applying Encrypt-then-MAC

   Once the use of encrypt-then-MAC has been negotiated, processing of
   TLS/DTLS packets switches from the standard:

   encrypt( data || MAC || pad )

   to the new:

   encrypt( data || pad ) || MAC

   with the MAC covering the entire packet up to the start of the MAC
   value.  In TLS [2] notation, the MAC calculation for TLS 1.0 without
   the explicit Initialization Vector (IV) is:

   MAC(MAC_write_key, seq_num +
       TLSCipherText.type +
       TLSCipherText.version +
       TLSCipherText.length +
       ENC(content + padding + padding_length));
...
   and for TLS 1.1 and greater with an explicit IV is:

   MAC(MAC_write_key, seq_num +
       TLSCipherText.type +
       TLSCipherText.version +
       TLSCipherText.length +
       IV +
       ENC(content + padding + padding_length));
...

```

# 13-1

```c
     // do serve listens from PF_PACKET socket
void do_serve();
  |  
  |  // process rx actually captures the packet
  |
void* process_rx(const int fd, char* rx_ring, int* len);
  |
  |  // sniff packet lets sniff action handles the packet,
  |  // if it's TCP
  |
void sniff_packet(void* packet);
  |
  |  // by examining TLS flag, it gathers data from Client Hello, Server Hello,
  |  // etc untils it hits Client Key Exchange
  |  
void sniff_action(uint8_t* dataraw);
  |
  |  // if it's Client Key Exchange, it runs the process of
  |  // hijacking master secret
  ------>  int hijack_key();
  |
  |  // if it successfully hijacked master secret
  |  // it's time to decrypt the client message!
  ------> int cbc256_decrypt(uint8_t* enc_msg, int enclen, uint8_t* cbc_key, uint8_t* cbc_iv, uint8_t* plain_msg);

```


# 13

```shell

./mitm.out


```

# 14

```shell

packet RX: 7 
dst mac: 1a:fe:a2:8e:77:09
dst address: 192.168.64.6
handshake: client hello
slen: 116

packet RX: 8 
dst mac: 8e:ee:03:c8:56:22
dst address: 192.168.62.6

packet RX: 9 
dst mac: 8e:ee:03:c8:56:22
dst address: 192.168.62.6
handshake: server hello

packet RX: 10 
dst mac: 1a:fe:a2:8e:77:09
dst address: 192.168.64.6

packet RX: 11 
dst mac: 1a:fe:a2:8e:77:09
dst address: 192.168.64.6
handshake: client key exchange
declen: 48
session info len: 1998
session_hash: 32
1D85F4612C17261000958F5AB963D9D6FFE3E361800955246FB31D4B23A6ADB0
extended master secret: label + seedlen: 54
master: 
  454A17BE7F52ACBBFF414EC635D541F0CA9F7054065EEB02D38012CF5703EEDB3B5D0CAD4726C823DFF72D00C50A269C
key expansion: label + seedlen: 77
master keymat: 
  6960D327538039F7E56D2B32D29BBC3E7C4752802E73867511D3AEBD092C1E8A9CA0860FC19CC0AD821C7C917A8695983EE7B42874B65894B8C2835AD03A60EE91D39235A4827881CA7CE057CC11244C78A2DA9DF111EFC53D45FFB3EFEC92182BD69CFAA449183E6BB01B622DF473F25D6F35707BA1923A57333FCEF37BB4FE8056C5E26F57BD043791713C844BCD7D003452E63B3FF51FCB0FA3EDF6A2861D

packet RX: 12 
dst mac: 8e:ee:03:c8:56:22
dst address: 192.168.62.6
handshake: new session ticket

```


# 15

```shell
    0070 - 05 5f 50 8c ee 01 9b ac-31 58 dc c3 d6 a7 05 66   ._P.....1X.....f
    0080 - fc 58 3f 9f ac 0f b7 0f-0c 3e 1f e1 9b 8c 80 a6   .X?......>......
    0090 - 49 7d 20 57 93 b7 8e 6a-9e 99 47 a6 61 41 f5 7e   I} W...j..G.aA.~
    00a0 - fb 1d 46 41 06 08 3f 2a-09 8a 70 7a 5d 37 5e 92   ..FA..?*..pz]7^.

    Start Time: 1748389568
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
i see dead people


```

# 16
```shell
packet RX: 17 
dst mac: 1a:fe:a2:8e:77:09
dst address: 192.168.64.6
message: payloadlen: 80
    😈 TLSv1.2 hijacked message 😈
    i see dead people


packet RX: 18 
dst mac: 8e:ee:03:c8:56:22
dst address: 192.168.62.6


```