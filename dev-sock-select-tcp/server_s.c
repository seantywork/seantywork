#include "server_s.h"
   
struct sockaddr_in servaddr;
int servlen;

int client_socket[MAX_CONN];
int opt = TRUE;   
int max_sd;
int sd;
int activity;
int new_socket;
int sock_added = FALSE;
int valread;

fd_set readfds;

void comm() { 


    for (int i = 0; i < MAX_CONN; i ++) { 


        sd = client_socket[i];

        char buff[MAX_BUFF] = {0}; 
        char wbuff[MAX_BUFF] = {0};
        struct sockaddr_in peeraddr;

        if(FD_ISSET(sd, &readfds)){

            valread = read(sd, buff, MAX_BUFF);
            if(valread == 0){

                getpeername(sd, (SA*)&peeraddr, (socklen_t*)&servlen);
                printf("client disconnected: ip=%s, port=%d\n",
                    inet_ntoa(peeraddr.sin_addr),
                    ntohs(peeraddr.sin_port)
                );
                close(sd);
                client_socket[i] = 0;
            }else{

                
                strcat(wbuff, "SERVER RESP: ");

                strcat(wbuff, buff);

                send(sd, wbuff, strlen(wbuff), 0);
            }

        }


    } 
} 
   
int main() 
{ 
    int sockfd;


    for (int i = 0; i < MAX_CONN; i ++){

        client_socket[i] = 0;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else
        printf("socket successfully created\n"); 

    if( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,  
          sizeof(opt)) < 0 )   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    }   
     

    bzero(&servaddr, sizeof(servaddr)); 
   
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
   
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed\n"); 
        exit(EXIT_FAILURE); 
    } 
   
    if(make_socket_non_blocking(sockfd) < 0){
        printf("non-blocking failed\n");
        exit(EXIT_FAILURE);
    }
    
    if ((listen(sockfd, 5)) != 0) { 
        printf("listen failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        servlen = sizeof(servaddr); 
    }

   
    while(TRUE){

        FD_ZERO(&readfds);

        FD_SET(sockfd, &readfds);

        max_sd = sockfd;

        for (int i= 0 ; i < MAX_CONN; i ++){

            sd = client_socket[i];

            if(sd > 0){
                FD_SET(sd, &readfds);
            }

            if (sd > max_sd){
                max_sd = sd;
            }


        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0 ) && (errno != EINTR)){
            printf("select error\n");
        }

        if (FD_ISSET(sockfd, &readfds)){

            new_socket = accept(sockfd, (SA* )&servaddr, (socklen_t*)&servlen);

            if (new_socket < 0){
                perror("accept error");
                exit(EXIT_FAILURE);
            }

            printf("new conn: fd=%d, ip=%s, port=%d\n", 
                new_socket, 
                inet_ntoa(servaddr.sin_addr), 
                ntohs(servaddr.sin_port) 
            );


            if(make_socket_non_blocking(new_socket) < 0){
                printf("non-blocking failed\n");
                continue;
            }
    

            for (int i = 0 ; i < MAX_CONN; i ++){

                if(client_socket[i] == 0){
                    client_socket[i] = new_socket;
                    printf("added new conn at: %d\n", i);
                    sock_added = TRUE;
                    break;
                }
            }

            if(sock_added != TRUE){
                printf("connection max reached\n");
                if(close(new_socket)){
                    printf("refusing incoming conn\n");
                }else{
                    printf("error closing conn\n");
                    exit(EXIT_FAILURE);
                }
            } else {
                sock_added = FALSE;
            }

        }

        comm();




    }
   

    return EXIT_SUCCESS;
}