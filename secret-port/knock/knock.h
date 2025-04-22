
#include <stdarg.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <pthread.h>
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

#define CONF_RING_FRAMES 2
#define FRAME_SIZE 2048
#define CONF_DEVICE "veth02"


#define SOCK_PROTOCOL(ringtype) htons(ETH_P_ALL)
#define SOCKADDR_PROTOCOL htons(ETH_P_ALL)

#define TX_DATA_OFFSET TPACKET_ALIGN(sizeof(struct tpacket2_hdr))
#define RX_DATA_OFFSET TX_DATA_OFFSET + 34


#define RETURN_ERROR(lvl, msg) \
    do                         \
    {                          \
        fprintf(stderr, msg);  \
        return lvl;            \
    } while (0);


void handle_error(const char* msg, int error);

void set_affinity(int8_t cpu);

void view_packet(void* packet);

int init_ring_daddr(int fd, const char* ringdev, const int ringtype, struct sockaddr_ll* dest_daddr);

char* init_packetsock_ring(int fd, int ringtype, int tx_mmap, struct sockaddr_ll* dest_daddr);

int init_packetsock(char** ring, int ringtype, int tx_mmap, struct sockaddr_ll* dest_daddr);

int exit_packetsock(int fd, char* ring, int tx_mmap);



void* process_rx(const int fd, char* rx_ring, int* len);

void process_rx_release(char* packet);

void rx_flush(void* ring);

void do_rx();


