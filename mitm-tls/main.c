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

#define SOCK_PROTOCOL(ringtype) htons(ETH_P_ALL)
#define SOCKADDR_PROTOCOL htons(ETH_P_ALL)

#define TX_DATA_OFFSET TPACKET_ALIGN(sizeof(struct tpacket2_hdr))
#define RX_DATA_OFFSET TX_DATA_OFFSET + 34

static EVP_PKEY* priv_key = NULL;
static RSA* rsa_priv_key = NULL;
static int priv_keylen = 0;

static EVP_CIPHER* cipher;
static unsigned char* gcm_key;
static unsigned char* gcm_iv;
static unsigned char* gcm_tag;

#define IVLEN 12
#define TAGLEN 128 / 8

static int rsa_decrypt(uint8_t* enc_msg, uint8_t* plain_msg){

    char* dec_msg = (char*)malloc(RSA_size(rsa_priv_key));
    int dec_len = RSA_private_decrypt(
                priv_keylen,
                (unsigned char*)enc_msg,
                (unsigned char*)dec_msg,
                rsa_priv_key,
                RSA_PKCS1_OAEP_PADDING
                );


    printf("declen: %d\n", dec_len);

    memcpy(plain_msg, (uint8_t*)dec_msg, dec_len);

    free(dec_msg);    

    return dec_len;
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

    printf("data: %s\n", data);


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
    rsa_priv_key = EVP_PKEY_get1_RSA(priv_key);
    priv_keylen = RSA_size(rsa_priv_key);

    cipher = EVP_aes_256_gcm();

    do_serve();

    RSA_free(rsa_priv_key);
    EVP_PKEY_free(priv_key);

    return 0;
}