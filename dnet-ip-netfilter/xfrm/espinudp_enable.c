#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <unistd.h>


#define UDP_PORT 4500

int main(int argc, char** argv){
    int fd;
    struct sockaddr_in server_addr, client_addr;
    int client_struct_length = sizeof(client_addr);
    int type = UDP_ENCAP_ESPINUDP;
    if(argc != 2){
        printf("wrong arg count: %d\n", argc);
        printf("needs server address\n");
        return -1;
    }
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(fd < 0){
        printf("error while creating socket\n");
        return -1;
    }
    printf("socket created successfully\n");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(UDP_PORT);
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
    if(bind(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("couldn't bind to the port\n");
        return -1;
    }

	if (setsockopt(fd, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0){
        printf("failed to set socket option for udp encap\n");
        return -1;
    }
    printf("socket set for udp encap traffic\n");
    for(;;){
        sleep(1);
    }
    close(fd);    
    return 0;
}
