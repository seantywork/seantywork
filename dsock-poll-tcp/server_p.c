#include <server_p.h>





int create_socket()
{
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    int OPT = 1;
    
    if( setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&OPT,  
          sizeof(OPT)) < 0 )   
    {   
        perror("setsockopt");   
        return -1;   
    } 


    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);



    int bindResult = bind(server_socket, (struct sockaddr *)&addr, sizeof(addr));
    if (bindResult == -1)
    {
        perror("bindResult");
        return -2;
    }


    int nonblockResult = make_socket_non_blocking(server_socket);

    if (nonblockResult < 0){
        perror("nonblockResult");
        return -3;
    }


    int listenResult = listen(server_socket, 5);
    if (listenResult == -1)
    {
        perror("listenResult");
        return -4;
    }

    printf("server start\n");
    return server_socket;
}

int wait_client(int server_socket)
{
    struct pollfd pollfds[MAX_CLIENTS + 1];
    pollfds[0].fd = server_socket;
    pollfds[0].events = POLLIN | POLLPRI;

    for (int i = 1; i < MAX_CLIENTS + 1; i++)
    {

        pollfds[i].fd = 0;
        pollfds[i].events = POLLIN | POLLPRI;


    }

    int useClient = 0;

    while (1)
    {
        // printf("useClient => %d\n", useClient);
        int pollResult = poll(pollfds, MAX_CLIENTS + 1, -1);
        printf("poll: %d\n", pollResult);
        if (pollResult > 0)
        {
            if (pollfds[0].revents & POLLIN)
            {
                struct sockaddr_in cliaddr;
                int addrlen = sizeof(cliaddr);
                int client_socket = accept(server_socket, (struct sockaddr *)&cliaddr, (socklen_t*)&addrlen);

                int nonblockResult = make_socket_non_blocking(client_socket);

                if (nonblockResult < 0){
                    printf("accpet non block failed: %d\n", nonblockResult);
                    continue;
                }


                printf("accept success %s\n", inet_ntoa(cliaddr.sin_addr));
                for (int i = 1; i < MAX_CLIENTS + 1; i++)
                {
                    if (pollfds[i].fd == 0)
                    {

                        pollfds[i].fd = client_socket;
                        useClient++;
                        break;
                    }
                }
            }
            for (int i = 1; i < MAX_CLIENTS + 1; i++)
            {
                if (pollfds[i].fd > 0 && pollfds[i].revents & POLLIN)
                {
                    char rbuf[SIZE] = {0};
                    char wbuf[SIZE] = {0};
                    int bufSize = read(pollfds[i].fd, rbuf, SIZE);
                    if (bufSize == -1)
                    {
                        pollfds[i].fd = 0;
                        pollfds[i].events = 0;
                        pollfds[i].revents = 0;
                        useClient--;
                        printf("client error\n");
                    }
                    else if (bufSize == 0)
                    {
                        pollfds[i].fd = 0;
                        pollfds[i].events = 0;
                        pollfds[i].revents = 0;
                        useClient--;

                        printf("client eof\n");
                    }
                    else
                    {

                        printf("From client: %s\n", rbuf);

                        sleep(WAIT);

                        strcat(wbuf, "SERVER ECHO: ");

                        strcat(wbuf, rbuf);

                        write(pollfds[i].fd, wbuf, 1024);

                    }
                } 
            }
        }
    }
}

int main()
{
    int server_socket = create_socket();

    int client_socket = wait_client(server_socket);

    printf("server end\n");

    close(client_socket);
    close(server_socket);

    return 0;
}