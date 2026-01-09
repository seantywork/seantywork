#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

struct interface {
    int     index;
    int     flags;     
    long    speed;      
    int     duplex;    
    char    name[IF_NAMESIZE + 1];
};


static int get_interface_info(const int fd, struct ifreq *const ifr, struct interface *const info){

    struct ethtool_cmd  cmd;
    int result;

    if (ioctl(fd, SIOCGIFFLAGS, ifr) == -1){
        info->flags = 0;
    } else {
        info->flags = ifr->ifr_flags;
    }


    ifr->ifr_data = (void *)&cmd;
    cmd.cmd = ETHTOOL_GSET; 
    if (ioctl(fd, SIOCETHTOOL, ifr) == -1) {
        info->speed = -1L;
        info->duplex = DUPLEX_UNKNOWN;
    } else {
        info->speed = ethtool_cmd_speed(&cmd);
        info->duplex = cmd.duplex;
    }

    do {
        result = close(fd);
    } while (result == -1 && errno == EINTR);
    if (result == -1){
        return errno;
    }


    return 0;
}


static int get_interface_by_name(char *const name, struct interface *const info){

    int             socketfd, result;
    struct ifreq    ifr;


    socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (socketfd == -1){
        return errno;
    }

    strncpy(ifr.ifr_name, name, IF_NAMESIZE);
    if (ioctl(socketfd, SIOCGIFINDEX, &ifr) == -1) {
        do {
            result = close(socketfd);
        } while (result == -1 && errno == EINTR);
        return errno = ENOENT;
    }

    info->index = ifr.ifr_ifindex;
    strncpy(info->name, name, IF_NAMESIZE);
    info->name[IF_NAMESIZE] = '\0';

    return get_interface_info(socketfd, &ifr, info);
}

int main(){

    struct interface iface;
    int arg;

    if (get_interface_by_name("eno1", &iface) != 0) {
        fprintf(stderr, "%s: No such interface.\n", "eno1");
        return -1;
    }

    printf("%s: Interface %d", iface.name, iface.index);
    if (iface.flags & IFF_UP){
        printf(", up");
    }

    if (iface.duplex == DUPLEX_FULL){
        printf(", full duplex");
    }else{
        if (iface.duplex == DUPLEX_HALF){
            printf(", half duplex");
        }
    }

    if (iface.speed > 0){
        printf(", %ld Mbps", iface.speed);
    }

    printf("\n");
}