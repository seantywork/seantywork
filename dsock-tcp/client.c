

#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()
#define MAX 80
#define PORT 8080
#define SA struct sockaddr
void comm(int sockfd)
{
    char buff[1024];
    int n;
    for (;;) {
        
        memset(buff, 0, 1024);
        
        printf("client message : ");
        n = 0;

        fgets(buff, 1024, stdin);

        write(sockfd, buff, sizeof(buff));

        memset(buff, 0, 1024);
        
        read(sockfd, buff, sizeof(buff));
        
        printf("server message : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("client exit\n");
            break;
        }
    }
}
 
int main()
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }

    bzero(&servaddr, sizeof(servaddr));
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);
 

    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))
        != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server\n");
 

    comm(sockfd);
 
    close(sockfd);
}