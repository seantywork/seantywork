#include "knock.h"


void handle_error(const char* msg, int error){

    if (error != 0){

        errno = error;
        perror(msg);
        _exit(error);
    }
}

void set_affinity(int8_t cpu){

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    handle_error("pthread_set_affinity_np", pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset));
}



void view_packet(void* packet){

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

    ip_addr.s_addr = ntohl(ip_header->daddr);

    printf("dst address: %s\n", inet_ntoa(ip_addr));

    printf("data: %s\n", data);


}

int init_ring_daddr(int fd, const char* ringdev, const int ringtype, struct sockaddr_ll* dest_daddr){

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


    memcpy(dest_daddr, &ring_daddr, sizeof(dest_daddr));

    return 0;
}




char* init_packetsock_ring(int fd, int ringtype, int tx_mmap, struct sockaddr_ll* dest_daddr){

    struct tpacket_req tp;
    char*			   ring;
    int				   packet_version = TPACKET_V2;

    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &packet_version, sizeof(packet_version)))
    {
        perror("setsockopt packet version");
        return NULL;
    }


    tp.tp_block_size = FRAME_SIZE * 2;
    tp.tp_frame_size = FRAME_SIZE;
    tp.tp_frame_nr	 = CONF_RING_FRAMES;
    tp.tp_block_nr	 = (tp.tp_frame_nr * tp.tp_frame_size) / tp.tp_block_size;


    if (init_ring_daddr(fd, CONF_DEVICE, ringtype, dest_daddr))
        return NULL;


    if (ringtype == PACKET_TX_RING & !tx_mmap){
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

int init_packetsock(char** ring, int ringtype, int tx_mmap, struct sockaddr_ll* dest_daddr){
    int fd;

    fd = socket(PF_PACKET, SOCK_RAW, SOCK_PROTOCOL(ringtype));
    if (fd < 0)
        RETURN_ERROR(-1, "Root priliveges are required\nsocket() rx. \n");

    if (ring){

        *ring = init_packetsock_ring(fd, ringtype, tx_mmap, dest_daddr);

        if (!tx_mmap)
            return fd;

        if (!*ring){

            close(fd);
            return -1;
        }
    }

    return fd;
}

int exit_packetsock(int fd, char* ring, int tx_mmap){

    if (tx_mmap && munmap(ring, CONF_RING_FRAMES * FRAME_SIZE)){
        perror("munmap");
        return 1;
    }

    if (close(fd)){
        perror("close");
        return 1;
    }

    return 0;
}



int main(int argc, char** argv){

    printf("set affinity: 0\n");
    set_affinity(0);

    printf("using interface: %s\n", CONF_DEVICE);

    do_rx();

}