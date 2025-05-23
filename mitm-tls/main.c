#include <stdarg.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <inttypes.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


#define CONF_RING_FRAMES 2
#define FRAME_SIZE 2048
#define CONF_DEVICE "veth11"

#define PRIVKEY_PATH "./certs/server_priv.pem"
#define PUBKEY_PATH "./certs/server_pub.pem"

#define SOCK_PROTOCOL(ringtype) htons(ETH_P_ALL)
#define SOCKADDR_PROTOCOL htons(ETH_P_ALL)

#define TX_DATA_OFFSET TPACKET_ALIGN(sizeof(struct tpacket2_hdr))
#define RX_DATA_OFFSET TX_DATA_OFFSET + 34

static uint8_t client_random[28] = {0};
static uint8_t server_random[28] = {0};
static uint8_t* server_pubkey = NULL;
static uint8_t* client_pubkey = NULL;


static EVP_PKEY* priv_key = NULL;

size_t premaster_secretlen = 0;
unsigned char *premaster_secret = NULL;


static EVP_CIPHER* cipher;
static unsigned char gcm_key[32];
static unsigned char gcm_iv[12];
static unsigned char gcm_tag[16];

#define IVLEN 12
#define TAGLEN 128 / 8

static uint8_t stage = 0x01;

static int hijack_premaster(){

    const unsigned char *pd = client_pubkey;
    EVP_PKEY *peer_pub_key = d2i_PUBKEY(NULL, &pd, 32);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv_key, NULL);

    if(EVP_PKEY_derive_init(dctx) != 1){
        printf("derive init failed\n");
        return -1;
    }

    if(EVP_PKEY_derive_set_peer(dctx, peer_pub_key) != 1){
        printf("derive set peer failed\n");
        return -1;
    }

    if(EVP_PKEY_derive(dctx, NULL, &premaster_secretlen) != 1){
        printf("derive get len failed\n");
        return -1;
    }
    for(int i = 0; i < 32; i++){
        printf("%02x", pd[i]);
    }
    printf("\n");

    printf("premaster_secretlen: %d\n", premaster_secretlen);

    premaster_secret = OPENSSL_zalloc(premaster_secretlen);

    if(EVP_PKEY_derive(dctx, premaster_secret, &premaster_secretlen) != 1){
        printf("derive failed\n");
        return -1;
    }
    EVP_PKEY_CTX_free(dctx);
    return 0;
}

static int gcm256_384_decrypt(uint8_t* enc_msg, int enclen, uint8_t* plain_msg){

    int outlen, rv;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, cipher, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, NULL);
    EVP_DecryptInit(ctx, NULL, gcm_key, gcm_iv);
    //EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, 8);
    EVP_DecryptUpdate(ctx, plain_msg, &outlen, enc_msg, enclen);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, gcm_tag);
    rv = EVP_DecryptFinal(ctx, plain_msg, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    return rv;

}


static void sniff_action(uint8_t* dataraw){

    struct tcphdr* tcp_header = (struct tcphdr*)dataraw;

    uint8_t* tcp_data = dataraw + 32;

    if(tcp_header->psh){

        switch(stage){

            case 0x01:
    
                if((*tcp_data & 0x16) && (*(tcp_data + 5) & stage)){
    
                    printf("handshake: client hello\n");
                } else {
                    break;
                }

                memcpy(client_random, tcp_data + 15, 28);
    
                stage = 0x02;
    
                break;
    
            case 0x02:
    
                if((*tcp_data & 0x16) && (*(tcp_data + 5) & stage)){
    
                    printf("handshake: server hello\n");
                } else {
                    break;
                }


                memcpy(server_random, tcp_data + 15, 28);

                uint16_t tmp = 0;
                uint16_t hellolen = 0;
                uint16_t certlen = 0;

                memcpy(&tmp, tcp_data + 3, 2);

                hellolen = ntohs(tmp);

                memcpy(&tmp, tcp_data + 5 + hellolen + 3, 2);

                certlen = ntohs(tmp);
                
                if(*(tcp_data + 5 + hellolen + 5 + certlen + 5) & 0x0C){

                    uint8_t pubkeylen = *(tcp_data + 5 + hellolen + 5 + certlen + 12);

                    printf("server pubkey len: %02x\n", pubkeylen);

                    server_pubkey = (uint8_t*)malloc(pubkeylen);
    
                    memcpy(server_pubkey, tcp_data + 3 + hellolen + 3 + certlen + 13, pubkeylen);

                } else {

                    printf("server hello offset invalid\n");

                    break;

                }

                stage = 0x10;
    
                break;
    
            case 0x10:
    
                if((*tcp_data & 0x16) && (*(tcp_data + 5) & stage)){
    
                    printf("handshake: client key exchange\n");
                } else {
                    break;
                }

                uint8_t pubkeylen = *(tcp_data + 9);

                printf("client pubkey len: %02x\n", pubkeylen);

                client_pubkey = (uint8_t*)malloc(pubkeylen);

                memcpy(client_pubkey, tcp_data + 10, pubkeylen);
    
                hijack_premaster();

                stage = 0x04;
    
                break;
    
            case 0x04:
        
                if((*tcp_data & 0x16) && (*(tcp_data + 5) & stage)){
    
                    printf("handshake: new session ticket\n");
                } else {
                    break;
                }
    
                stage = 0x00;
    
                break;
    
            default:
                
                printf("message: \n");
    
                break;
        }

    }


}

static void sniff_packet(void* packet){

    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    uint8_t* data;
    struct in_addr ip_addr;

    eth_header = packet;
    ip_header = packet + sizeof(*eth_header);
    data = packet + sizeof(*eth_header) + sizeof(*ip_header);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                eth_header->h_dest[0], 
                eth_header->h_dest[1], 
                eth_header->h_dest[2], 
                eth_header->h_dest[3], 
                eth_header->h_dest[4],
                eth_header->h_dest[5]
                );

    ip_addr.s_addr = ip_header->daddr;

    printf("dst address: %s\n", inet_ntoa(ip_addr));

    if(ip_header->protocol == IPPROTO_TCP){

        sniff_action(data);

    } 

    return;


}


static int init_ring_daddr(int fd, const char* ringdev, const int ringtype, struct sockaddr_ll* dest_daddr){

    struct ifreq ifr;
    int	ifindex;
    struct sockaddr_ll ring_daddr;
    // get device index
    strcpy(ifr.ifr_name, ringdev);
    if (ioctl(fd, SIOCGIFINDEX, &ifr)){
        printf("ioctl\n");
        return -1;
    }
    ifindex = ifr.ifr_ifindex;
    memset(&ring_daddr, 0, sizeof(ring_daddr));

    ring_daddr.sll_family = AF_PACKET;
    ring_daddr.sll_protocol = SOCKADDR_PROTOCOL;
    ring_daddr.sll_ifindex  = ifindex;

    memcpy(dest_daddr, &ring_daddr, sizeof(struct sockaddr_ll));

    return 0;
}




static char* init_packetsock_ring(int fd, int ringtype, struct sockaddr_ll* dest_daddr){

    struct tpacket_req tp;
    char* ring;
    int	packet_version = TPACKET_V2;

    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &packet_version, sizeof(packet_version))){
        printf("setsockopt packet version");
        return NULL;
    }

    tp.tp_block_size = getpagesize();
    tp.tp_frame_size = FRAME_SIZE;
    tp.tp_frame_nr	 = CONF_RING_FRAMES;
    tp.tp_block_nr	 = (tp.tp_frame_nr * tp.tp_frame_size) / tp.tp_block_size;

    if (init_ring_daddr(fd, CONF_DEVICE, ringtype, dest_daddr)){
        printf("init ring\n");
        return NULL;
    }

    if (setsockopt(fd, SOL_PACKET, ringtype, (void*)&tp, sizeof(tp))){
        printf("setsockopt sol packet\n");
        return NULL;
    }

    ring = mmap(0, tp.tp_block_size * tp.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED){
        printf("mmap failed\n");
        return NULL;
    }

    return ring;
}

static int init_packetsock(char** ring, int ringtype, struct sockaddr_ll* dest_daddr){

    int fd;
    fd = socket(PF_PACKET, SOCK_RAW, SOCK_PROTOCOL(ringtype));
    if (fd < 0){

        printf("failed to create socket \n");
        return fd;
    }

    if (ring){
        *ring = init_packetsock_ring(fd, ringtype, dest_daddr);


        if (!*ring){
            close(fd);
            return -1;
        }
    }

    return fd;
}

static int exit_packetsock(int fd, char* ring, int tx_mmap){

    if (tx_mmap && munmap(ring, CONF_RING_FRAMES * FRAME_SIZE)){
        printf("munmap failed\n");
        return -1;
    }

    close(fd);

    return 0;
}


static void* process_rx(const int fd, char* rx_ring, int* len){

    int ret;
    struct tpacket2_hdr* header;
    struct pollfd pollset;


    for (int i = 0; i < CONF_RING_FRAMES; i++){
        
        header = (void*)rx_ring + (i * FRAME_SIZE);
        assert((((unsigned long)header) & (FRAME_SIZE - 1)) == 0);

        if (header->tp_status != TP_STATUS_AVAILABLE){

            pollset.fd		= fd;
            pollset.events	= POLLIN;
            pollset.revents = 0;
            ret				= poll(&pollset, 1, 1);
        }


        if (header->tp_status & TP_STATUS_USER){
            if (header->tp_status & TP_STATUS_COPY){
                printf("copy\n");
                continue;
            }
            *len = header->tp_len;

            return (void*)header;
        }
    }
    return NULL;
}

static void process_rx_release(char* packet){

    struct tpacket2_hdr* header = (struct tpacket2_hdr*)packet;
    header->tp_status = TP_STATUS_KERNEL;

}

static void rx_flush(void* ring){
    for (int i = 0; i < CONF_RING_FRAMES; i++){
        struct tpacket2_hdr* hdr = ring + (i * FRAME_SIZE);
        hdr->tp_status = TP_STATUS_KERNEL;
    }
}


void do_serve(){

    char *rxRing, *pkt;
    int	  rxFd;
    int	  len;

    struct sockaddr_ll rxdest_daddr;

    rxFd = init_packetsock(&rxRing, PACKET_RX_RING, &rxdest_daddr);
    if (rxFd < 0){
        printf("failed to init rx packet sock\n");
        return;
    }

    

    if (bind(rxFd, (struct sockaddr*)&rxdest_daddr, sizeof(rxdest_daddr)) != 0){
        printf("bind rxfd\n");
        return;
    }


    int needs_flush = 0;
    int count = 0;
    while(1){

        pkt = NULL;

        while (pkt = process_rx(rxFd, rxRing, &len)){

            uint8_t* off = ((void*)pkt) + RX_DATA_OFFSET;
            printf("server RX: %d \n", count);
            sniff_packet(off);
            printf("\n");
            process_rx_release(pkt);
            needs_flush = 1;
            count += 1;
            
        }

        if (needs_flush == 1){
            rx_flush(rxRing);
            needs_flush = 0;
        }

    }

    exit_packetsock(rxFd, rxRing, 1);

    return;
}


int main(){

    FILE* fp;

    printf("mitm using interface: %s\n", CONF_DEVICE);
    printf("mitm using privkey: %s\n", PRIVKEY_PATH);

    fp = fopen(PRIVKEY_PATH, "r");
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    cipher = EVP_aes_256_gcm();

    do_serve();

    if(client_pubkey != NULL){
        free(client_pubkey);
    }
    if(server_pubkey != NULL){
        free(server_pubkey);
    }
    if(premaster_secret != NULL){
        OPENSSL_clear_free(premaster_secret, premaster_secretlen);
    }

    return 0;
}