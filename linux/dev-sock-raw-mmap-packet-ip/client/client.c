
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
#include <signal.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/// The number of frames in the ring
//  This number is not set in stone. Nor are block_size, block_nr or frame_size
#define CONF_RING_FRAMES 2
#define FRAME_SIZE 2048
#define CONF_DEVICE "veth02"

// ethercat
//#define SOCK_PROTOCOL(ringtype) htons(0x88a4)
//#define SOCKADDR_PROTOCOL htons(0x88a4)

#define SOCK_PROTOCOL(ringtype) htons(ETH_P_ALL)
#define SOCKADDR_PROTOCOL htons(ETH_P_ALL)

/// Offset of data from start of frame
#define TX_DATA_OFFSET TPACKET_ALIGN(sizeof(struct tpacket2_hdr))
#define RX_DATA_OFFSET TX_DATA_OFFSET + 34

/// (unimportant) macro for loud failure
#define RETURN_ERROR(lvl, msg) \
    do                         \
    {                          \
        fprintf(stderr, msg);  \
        return lvl;            \
    } while (0);


int keepalive = 1;

static void stop_function(int signal) {
    puts("interactive attention signal caught.");
    keepalive = 0;
}


static uint8_t server_hw_addr[ETH_ALEN]= {
    0xaa,
    0xaa,
    0xaa,
    0x01,
    0x01,
    0x01,
};

static uint8_t client_hw_addr[ETH_ALEN]= {
    0xaa,
    0xaa,
    0xaa,
    0x02,
    0x02,
    0x02,
};

void handle_error(const char* msg, int error)
{
    if (error != 0)
    {
        errno = error;
        perror(msg);
        _exit(error);
    }
}

void set_affinity(int8_t cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    handle_error("pthread_set_affinity_np", pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset));
}

char*					  Ethernet_ifname = CONF_DEVICE;



static struct sockaddr_ll ring_daddr;
static struct sockaddr_ll dest_daddr;

static unsigned short ipcsum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

static uint8_t* make_ip_packet(int* newlen, int msglen, char* msg){


    int packetlen = sizeof(struct ethhdr) + sizeof(struct iphdr) + msglen;

    *newlen = packetlen;

    void* packet = (void*)malloc(packetlen);


    memset(packet, 0, packetlen);

    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    uint8_t* data;

    eth_header = packet;

    ip_header = packet + sizeof(*eth_header);

    data = packet + sizeof(*eth_header) + sizeof(*ip_header);

    memcpy(eth_header->h_dest, server_hw_addr, ETH_ALEN);
    memcpy(eth_header->h_source, client_hw_addr, ETH_ALEN);
    eth_header->h_proto = htons(0x0800);

    ip_header->ihl = 5;
    ip_header->version = IPVERSION;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + msglen);
    ip_header->id = 0;
    ip_header->frag_off = htons(0x4000);
    ip_header->ttl = IPDEFTTL;
    ip_header->saddr = inet_addr("192.168.10.2");
    ip_header->daddr = inet_addr("192.168.10.1");
    ip_header->protocol = 0xFD; // experiment
    ip_header->check = 0;

    ip_header->check = ipcsum((unsigned short *)ip_header, sizeof(struct iphdr) + msglen);

    memcpy(data, msg, msglen);

    return packet;
}

static void view_ip_packet(void* packet){

    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    uint8_t* data;

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

    printf("dst address: %d\n", ip_header->daddr);

    printf("data: %s\n", data);


}

/// create a linklayer destination address
//  @param ringdev is a link layer device name, such as "eth0"
static int init_ring_daddr(int fd, const char* ringdev, const int ringtype, struct sockaddr_ll* dest_daddr, uint8_t* hw_daddr)
{
    struct ifreq ifr;
    int			 ifindex;
    struct sockaddr_ll ring_daddr;
    // get device index
    strcpy(ifr.ifr_name, ringdev);
    if (ioctl(fd, SIOCGIFINDEX, &ifr))
    {
        perror("ioctl");
        return -1;
    }
    ifindex = ifr.ifr_ifindex;
    memset(&ring_daddr, 0, sizeof(ring_daddr));

    ring_daddr.sll_family	  = AF_PACKET;
    ring_daddr.sll_protocol = SOCKADDR_PROTOCOL;
    ring_daddr.sll_ifindex  = ifindex;
//    ring_daddr.sll_halen	  = ETH_ALEN;  
    //memcpy(&ring_daddr.sll_addr, hw_daddr, ETH_ALEN);

    memcpy(dest_daddr, &ring_daddr, sizeof(struct sockaddr_ll));

    return 0;
}




static char* init_packetsock_ring(int fd, int ringtype, int tx_mmap, struct sockaddr_ll* dest_daddr, uint8_t* hw_daddr)
{
    struct tpacket_req tp;
    char*			   ring;
    int				   packet_version = TPACKET_V2;

    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &packet_version, sizeof(packet_version)))
    {
        perror("setsockopt packet version");
        return NULL;
    }

    // tell kernel to export data through mmap()ped ring
//    tp.tp_block_size = getpagesize();
    tp.tp_block_size = FRAME_SIZE * 2;
    tp.tp_frame_size = FRAME_SIZE;
    tp.tp_frame_nr	 = CONF_RING_FRAMES;
//    tp.tp_block_nr	 = CONF_RING_FRAMES;
    tp.tp_block_nr	 = (tp.tp_frame_nr * tp.tp_frame_size) / tp.tp_block_size;

    {
        if (init_ring_daddr(fd, Ethernet_ifname, ringtype, dest_daddr, hw_daddr))
            return NULL;
    }

    if (ringtype == PACKET_TX_RING & !tx_mmap)
    {
        printf("no mmap\n");
        return NULL;
    }


    if (setsockopt(fd, SOL_PACKET, ringtype, (void*)&tp, sizeof(tp)))
        RETURN_ERROR(NULL, "setsockopt() ring\n");

    // open ring
    ring = mmap(0, tp.tp_block_size * tp.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED)
        RETURN_ERROR(NULL, "mmap()\n");

    return ring;
}

static int init_packetsock(char** ring, int ringtype, int tx_mmap, struct sockaddr_ll* dest_daddr, uint8_t* hw_daddr)
{
    int fd;

    // open packet socket
    fd = socket(PF_PACKET, SOCK_RAW, SOCK_PROTOCOL(ringtype));
    if (fd < 0)
        RETURN_ERROR(-1, "Root priliveges are required\nsocket() rx. \n");

    if (ring)
    {
        *ring = init_packetsock_ring(fd, ringtype, tx_mmap, dest_daddr, hw_daddr);

        if (!tx_mmap)
            return fd;

        if (!*ring)
        {
            // printf("Closing fd\n");
            close(fd);
            return -1;
        }
    }

    return fd;
}

static int exit_packetsock(int fd, char* ring, int tx_mmap)
{
    if (tx_mmap && munmap(ring, CONF_RING_FRAMES * FRAME_SIZE))
    {
        perror("munmap");
        return 1;
    }

    if (close(fd))
    {
        perror("close");
        return 1;
    }

    return 0;
}


static int process_tx(int fd, char* ring, const char* pkt, size_t pktlen, int offset, int tx_mmap, struct sockaddr_ll* dest_daddr)
{
    static int ring_offset = 0;

    struct tpacket2_hdr* header;
    struct pollfd		 pollset;
    char*				 off;
    int					 ret;

    if (tx_mmap)
    {

        header = (void*)ring + (ring_offset * FRAME_SIZE);
        assert((((unsigned long)header) & (FRAME_SIZE - 1)) == 0);
        while (header->tp_status != TP_STATUS_AVAILABLE)
        {
            // if none available: wait on more data
            pollset.fd		= fd;
            pollset.events	= POLLOUT;
            pollset.revents = 0;
            ret				= poll(&pollset, 1, 1 /* don't hang */);
            if (ret < 0)
            {
                if (errno != EINTR)
                {
                    perror("poll");
                    return -1;
                }
                return 0;
            }
        }

        // fill data
        off = ((void*)header) + TX_DATA_OFFSET + offset;
        memcpy(off, pkt, pktlen);

        // fill header
        header->tp_len	  = pktlen;
        header->tp_status = TP_STATUS_SEND_REQUEST;

        // increase consumer ring pointer
        ring_offset = (ring_offset + 1) & (CONF_RING_FRAMES - 1);

        if (send(fd, NULL, 0, 0) < 0)

        {
            perror("sendto");
            return -1;
        }
    }
    else
    {
        off = (void*)pkt;

        if (sendto(fd, off, pktlen, 0, (struct sockaddr*)&dest_daddr, sizeof(dest_daddr)) < 0)
        {
            perror("sendto");
            return -1;
        }
    }

    // printf("Tx:%d\n",ring_offset);fflush(stdout);

    return 0;
}


void do_req()
{
    int	  status = 1;
    char *txRing, *rxRing, *pkt;
    int   txFd;
    int	  rxFd;
    int	  len;

    struct sockaddr_ll txdest_daddr;
    struct sockaddr_ll rxdest_daddr;

    txFd = init_packetsock(&txRing, PACKET_TX_RING, 1, &txdest_daddr, server_hw_addr);
    if (txFd < 0){
        printf("failed to init tx packet sock\n");
        return;
    }

    
    if (bind(txFd, (struct sockaddr*)&txdest_daddr, sizeof(txdest_daddr)) != 0)
    {
        printf("bind txfd\n");
        return;
    }


    int	  offset = 0;

    int got_reply = 0;


    char* hellodata = "hello friend";

    int newlen = 0;
    int msglen = strlen(hellodata);


    uint8_t* new_packet = make_ip_packet(&newlen, msglen, hellodata);


    process_tx(txFd, txRing, new_packet, newlen, offset, 1, &dest_daddr);

    int go = 0;
    while(keepalive == 1){

//        sleep(1);
        struct timespec remaining, request;
        
        request.tv_sec = 0;
        request.tv_nsec = 200000000L;
         
        int response = nanosleep(&request, &remaining);
        printf("tx: %d\n", go);

        process_tx(txFd, txRing, new_packet, newlen, offset, 1, &dest_daddr);

        go += 1;
    }


    if (exit_packetsock(txFd, txRing, 1))
        return;

    free(new_packet);


    return;
}


int main(int argc, char** argv)
{
    if (argc > 1)
        Ethernet_ifname = argv[1];

    if (signal(SIGINT, stop_function) == SIG_ERR) {
        printf("signal set error\n");
        return EXIT_FAILURE;
    }

    printf("set affinity: 0\n");
    set_affinity(0);

    printf("using interface: %s\n", Ethernet_ifname);

    do_req();

}