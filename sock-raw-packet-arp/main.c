#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>


#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60


struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[MAC_LENGTH];
    uint8_t sender_ip[IPV4_LENGTH];
    uint8_t target_mac[MAC_LENGTH];
    uint8_t target_ip[IPV4_LENGTH];
}__attribute__ ((__packed__));




static int neigh_init(char* ifname, int* fd, int* ifidx, uint32_t *saddr_be, uint32_t* saddr_mask_be, uint8_t* hwaddr_s){

    struct sockaddr_in *addr;
    struct ifreq ifr;
    char* address;

    printf("neigh init for %s\n", ifname);
    int err = -1;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        printf("tmp arp socket failed\n");
        return 0;
    }

    strcpy(ifr.ifr_name, ifname);

    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        printf("err ioctl ifinx\n");
        return -1;
    }
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        printf("err ioctl hwaddr\n");
        return -2;
    }

    memcpy(hwaddr_s, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if(ioctl(sd, SIOCGIFADDR, &ifr) < 0){
        printf("err ioctl if addr\n");
        return -3;
    }

    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    //address = inet_ntoa(addr->sin_addr);
    *saddr_be = addr->sin_addr.s_addr;

    if( ioctl( sd, SIOCGIFNETMASK, &ifr) == -1){
        printf("err ioctl netmask\n");
        return -4;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    //address = inet_ntoa(addr->sin_add);
    *saddr_mask_be = addr->sin_addr.s_addr;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        printf("arp socket bind failed\n");
        return -5;
    }

    printf("neigh init success for %s\n", ifname);

    *fd = sd;
    *ifidx = ifr.ifr_ifindex;

    return 0;
}


static int neigh_exchange(int fd, int ifindex, uint8_t *dst_mac, uint8_t *src_mac, uint32_t dst_ip, uint32_t src_ip){
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    send_req->h_proto = htons(ETH_P_ARP);

    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, ETH2_HEADER_LEN + sizeof(struct arp_header), 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        printf("sendto(): error arp\n");
        goto out;
    }


    length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);

    if (length == -1) {
        printf("recvfrom(): error arp\n");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        printf("recvfrom(): not an arp packet\n");
        goto out;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        printf("recvfrom(): not an arp reply\n");
        goto out;
    }
    printf("received arp len=%ld\n", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));
    printf("sender ip: %s\n", inet_ntoa(sender_a));

    memcpy(dst_mac, arp_resp->sender_mac, MAC_LENGTH);

    err = 0;
out:
    return err;
}


int main(int argc, char** argv){

    system("ip neigh flush all");

    if(argc != 3){
        printf("needs two args:\n");
        printf("    route interface\n");
        printf("    dst addr\n ");
        return -1;
    }

	struct in_addr inaddr;

    int fd;
    int ifidx;
    uint32_t saddr_be = 0;
    uint32_t saddr_mask_be = 0; 
    uint8_t hwaddr_s[MAC_LENGTH] = {0};

    uint32_t src_ip = 0;
    uint32_t src_mask = 0;
    uint32_t src_start = 0;
    uint32_t src_end = 0;

    uint32_t dst_ip_be = inet_addr(argv[2]);
    uint32_t dst_ip = ntohl(dst_ip_be);

    uint8_t dst_mac[MAC_LENGTH] = {0};

    if(neigh_init(argv[1], &fd, &ifidx, &saddr_be, &saddr_mask_be, hwaddr_s)<0){
        return -1;
    }

    src_ip = ntohl(saddr_be);
    src_mask = ntohl(saddr_mask_be);
    src_start = src_ip & src_mask;
    src_end = src_start | ~src_mask;

    inaddr.s_addr = htonl(src_start);
    printf("route ip range start: %s\n", inet_ntoa(inaddr));
    inaddr.s_addr = htonl(src_end);
    printf("route ip range end:  %s\n", inet_ntoa(inaddr));
    inaddr.s_addr = htonl(dst_ip);
    printf("target ip : %s\n", inet_ntoa(inaddr));

    if(neigh_exchange(fd, ifidx, dst_mac, hwaddr_s, dst_ip_be, saddr_be) < 0){
        return -3;
    }

    printf("arp query success\n");

    printf("dst mac: ");
    for(int i = 0 ; i < MAC_LENGTH; i++){

        printf("%1x ",dst_mac[i]);

    }
    printf("\n");



}


