#include "client_p.h"

int SOCK_FD;

int connect_with_timeout(char* addr, int port, long timeout){

    int status, valread, client_fd;
    struct sockaddr_in serv_addr;

    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        
        printf("socket creation error\n");

        return -1;
    }
 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
 

    if (inet_pton(AF_INET, addr, &serv_addr.sin_addr) <= 0) {

        printf("invalid address, address not supported\n");
        return -2;
    }


    SOCK_FD = client_fd;

    struct timeval u_timeout;      
    u_timeout.tv_sec = 5;
    u_timeout.tv_usec = 0;
    

    if (setsockopt (SOCK_FD, SOL_SOCKET, SO_RCVTIMEO, &u_timeout, sizeof(u_timeout)) < 0){

        printf("set recv timeout\n");

        return -3;
    }
    

    if (setsockopt (SOCK_FD, SOL_SOCKET, SO_SNDTIMEO, &u_timeout, sizeof(u_timeout)) < 0) {

        printf("set send timeout\n");
    
        return -4;
    }
    

    int rc = 0;
    
    int sockfd_flags_before;

    sockfd_flags_before = fcntl(SOCK_FD,F_GETFL,0);
    
    if(sockfd_flags_before < 0) {
    
        printf("failed to getfl\n");

        return -5;
    
    }
    
    

    if(fcntl(SOCK_FD, F_SETFL, sockfd_flags_before | O_NONBLOCK)<0){


        printf("failed to setfl\n");

        return -6;
    
    } 



 

    if (connect(SOCK_FD, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {

        if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {

            rc = -11;

        } else {
            
            struct timespec now;

            clock_gettime(CLOCK_MONOTONIC_RAW, &now);

            struct timespec deadline;


            do{

                clock_gettime(CLOCK_MONOTONIC_RAW, &deadline);

                int ms_until_deadline = ((deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_nsec - now.tv_nsec) / 1000000);
 
                if(ms_until_deadline > timeout) { 
                    rc = -10; 
                    break; 
                }
                
                struct pollfd pfds[] = { { .fd = SOCK_FD, .events = POLLOUT } };
                rc = poll(pfds, 1, ms_until_deadline);
                
                if(rc > 0) {
                    int error = 0; 
                    socklen_t len = sizeof(error);
                    int retval = getsockopt(SOCK_FD, SOL_SOCKET, SO_ERROR, &error, &len);
                    if(retval == 0) {
                        errno = error;
                    }
                    if(error != 0) {
                        rc = -11;
                    }
                }

            } while(rc == -11 && errno == EINTR);


            if(rc == -10) {
                
                errno = ETIMEDOUT;
                
            }

        }

    } 

    
    

    if(fcntl(SOCK_FD,F_SETFL,sockfd_flags_before ) < 0) {

        return -20;
    }

    return rc;
}

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

int main(){


    int stat = connect_with_timeout("127.0.0.1", 8080, 5000);


    if(stat < 0){

        printf("failed: %d\n", stat);

        return -1;
    }


    comm(SOCK_FD);

    close(SOCK_FD);

    return 0;
}