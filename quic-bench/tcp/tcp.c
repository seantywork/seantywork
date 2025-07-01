#include "tcp.h"


static int client(){

    int result = 0;
    int sockfd = -1;
    struct sockaddr_in servaddr;
    in_addr_t s_addr = inet_addr(SERVER_ADDR);
    int addr_port = SERVER_PORT;
    int keepalive = 1;
    int chunk = 0;
    int content_len = 0;
    int message_len = 0;
    float percent = 0;
    struct timeval t1, t2;

    uint64_t total_sent = 0;
    uint8_t data[INPUT_BUFF_CHUNK] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "socket creation failed\n");
        return -1;
    }
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = s_addr;
    servaddr.sin_port = htons(addr_port);

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))!= 0) {
        fprintf(stderr, "connection failed\n");
        return -2;
    }

    printf("connected, sending...\n");

    gettimeofday(&t1, NULL);

    while(keepalive){

        if(getrandom(data, INPUT_BUFF_CHUNK, 0) < 0){
            printf("getrandom failed\n");
            return -3;
        }

        int wb = write(sockfd, data, INPUT_BUFF_CHUNK);

        if(wb <= 0){       
            keepalive = 0;
            continue;
        }

        total_sent += (uint64_t)wb;

        percent = ((float)total_sent / (float)INPUT_BUFF_MAX) * 100;

        printf("progress: %.2f\n", percent);

        if(total_sent > INPUT_BUFF_MAX){
            keepalive = 0;
            continue;
        }

    }

    if(total_sent <= INPUT_BUFF_MAX){
        printf("connection closed before sending completed\n");
        return -4;
    }

    gettimeofday(&t2, NULL);

    uint32_t seconds = t2.tv_sec - t1.tv_sec;      
    uint32_t ms = (t2.tv_usec - t1.tv_usec) / 1000;
    
    printf("sec: %lu ms: %lu\n", seconds, ms);
    printf("total sent: " "%" PRIu64 "\n", total_sent);

    return 0;
}



static int server(){
    
    int sockfd, connfd = -1; 
    struct sockaddr_in servaddr, cli; 
    int keepalive = 1;


    in_addr_t s_addr = INADDR_ANY;

    int addr_port = SERVER_PORT;
    int enable = 1;
    int clilen = sizeof(cli); 

    uint8_t data[INPUT_BUFF_CHUNK] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        fprintf(stderr,"socket creation failed...\n"); 
        return -1;
    } 

    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = s_addr; 
    servaddr.sin_port = htons(addr_port); 
   
    if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
        fprintf(stderr, "socket bind failed\n"); 
        return -2;
    } 
   
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        fprintf(stderr, "socket opt failed\n"); 
        return -3;
    }

    if ((listen(sockfd, 1)) != 0) { 
        fprintf(stderr,"socket listen failed\n"); 
        return -4;
    } 
    
    while(keepalive){

        connfd = accept(sockfd, (struct sockaddr*)&cli, (socklen_t*)&clilen); 
        if (connfd < 0) { 
            fprintf(stderr, "server accept failed\n"); 
            continue;
        }

        printf("client connected\n");
        printf("receiving...\n");

        while(keepalive){

            int valread = 0;

            while(valread < INPUT_BUFF_CHUNK){

                int rb = read(connfd, data + valread, INPUT_BUFF_CHUNK - valread);
                if (rb <= 0){
                    keepalive = 0;
                    break;
                } 
                valread += rb;

            }

            if(keepalive == 0){
                continue;
            }
        }

        close(connfd);

    }
    return 0;
}



static void help(){

    printf("option: [c|s]\n");
    printf("c: client mode\n");
    printf("s: server mode\n");
}


int main(int argc, char** argv){

    int result = 0;

    if(argc != 2){

        help();

        return -1;
    }

    if(strcmp(argv[1], "c") == 0){

        result = client();

    } else if(strcmp(argv[1], "s") == 0){

        result = server();

    } else {

        help();

        return -1;
    }

    return result;
}