#include "ncat.h"



void NCAT_keyboard_interrupt(){

    fprintf(stderr,"SIGINT. EXIT.\n");

    exit(0);

}


int NCAT_parse_args(int argc, char** argv){


    if(argc < 2){

        printf("needs argument: [-l|--listen] host port\n");

        return -1;
    }


    int argc_nohp = argc - 2;


    for(int i = 0 ; i < argc_nohp; i ++){


        if(
            (strcmp(argv[i], "--listen") == 0)
            || (strcmp(argv[i], "-l") == 0)
        ){

            ncat_opts.mode_listen = 1;

        }


    }

    if(ncat_opts.mode_listen == 0){
        ncat_opts.mode_client = 1;
    }


    int host_idx = argc_nohp;
    int port_idx = argc_nohp + 1;


    ncat_opts.host = argv[host_idx];
    ncat_opts.port = argv[port_idx];




    return 0;
}



void NCAT_free(){

    if(serve_content != NULL){

        free(serve_content);
    }

}


int NCAT_runner(){

    int status = 0;

    pthread_t thread_id;

    int flags_org = 0;

    if(ncat_opts.mode_listen == 1){

        int flags = 0;

        if(pipe(ncat_opts._server_sig) != 0){

            printf("failed to initiate server sig\n");

            return -1;

        }

        flags |= O_NONBLOCK;

        if (fcntl(ncat_opts._server_sig[0], F_SETFL, flags) != 0){

            printf("failed to setup server sig\n");

            return -2;
        }

        flags_org = fcntl(STDIN_FILENO,F_GETFL,0);

        if (fcntl(STDIN_FILENO, F_SETFL, flags) != 0){

            printf("failed to setup server stdin\n");

            return -3;
        }

    }


    pthread_create(&thread_id, NULL, NCAT_get_thread, NULL);

    if(ncat_opts.mode_client == 1){

        status = NCAT_client();

        return status;

    }

    if(ncat_opts.mode_listen == 1){

        struct pollfd sig_wait = {.fd = ncat_opts._server_sig[0], .events = POLLIN};

        char sig_result[SERVER_SIG_LEN] = {0};    

        for(int count = 0; count < SERVER_SIG_TIMEOUT_COUNT; count++){

            switch(poll(&sig_wait, 1, SERVER_SIG_TIMEOUT_MS)){

                case 1:
                    if (sig_wait.revents & POLLIN) {
  
                        ssize_t len = read(ncat_opts._server_sig[0], sig_result, SERVER_SIG_LEN);
    
                        count += SERVER_SIG_TIMEOUT_COUNT;

                        break;
                    }

                    break;
                default:

                    count += 1;

            }

        }

        if(strcmp(SERVER_SIG_DONE, sig_result) != 0){

            if(serve_content != NULL){

                free(serve_content);
                serve_content = NULL;
            }
        }

        close(ncat_opts._server_sig[0]);

        if (fcntl(STDIN_FILENO, F_SETFL, flags_org) != 0){

            printf("failed to setup server stdin to original\n");

            return -3;
        }

        status = NCAT_listen_and_serve();


        return status;

    } 


    fprintf(stderr, "unsupported mode\n");

    return -10;

}



int NCAT_client(){


    int sockfd;
    struct sockaddr_in servaddr;


    in_addr_t s_addr = inet_addr(ncat_opts.host);

    int addr_port = atoi(ncat_opts.port);


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
        return -1;
    }

    ncat_opts._client_sockfd = sockfd;
    ncat_opts._client_sock_ready = 1;

    int keepalive = 1;

    NCAT_COMMS comms; 

    memset(&comms, 0, sizeof(comms));

    while(keepalive){

        char* wbuff = NULL;

        int chunk = 1;

        int content_len = 0;

        wbuff = (char*)malloc(INPUT_BUFF_CHUNK * chunk);

        memset(wbuff, 0, INPUT_BUFF_CHUNK * chunk);

        char* content_ptr = wbuff + content_len;

        char c = 0;

        while((c = fgetc(stdin)) != '\n'){

            *content_ptr = c; 

            content_len += 1;

            if(content_len == (INPUT_BUFF_CHUNK * chunk)){

                chunk += 1;

                wbuff = (char*)realloc(wbuff, INPUT_BUFF_CHUNK * chunk);

            }

            content_ptr = wbuff + content_len;
            
        }

        comms.datalen = htonl(content_len);
        comms.data = (uint8_t*)wbuff;

        int wb = write(sockfd, &comms, sizeof(uint32_t) + content_len);

        if(wb <= 0){

            keepalive = 0;

            continue;
        }
        

    }   

    ncat_opts._client_sock_ready = 0;

    close(sockfd);

 
    return 0;
}


int NCAT_listen_and_serve(){

    
    int sockfd, connfd; 
    struct sockaddr_in servaddr, cli; 

    in_addr_t s_addr = inet_addr(ncat_opts.host);
    
    int addr_port = atoi(ncat_opts.port);

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
        return -1; 
    } 
   
    if ((listen(sockfd, 5)) != 0) { 
        fprintf(stderr,"socket listen failed\n"); 
        return -1; 
    } 
    
    
    int clilen = sizeof(cli); 

    NCAT_COMMS comms;

    memset(&comms, 0, sizeof(comms));

    while(_exit_prog != 1){


        connfd = accept(sockfd, (struct sockaddr*)&cli, (socklen_t*)&clilen); 
        if (connfd < 0) { 
            fprintf(stderr, "server accept failed\n"); 
            return -1; 
        } 
    

        int valwrite =0;

        if(serve_content != NULL){

            uint32_t contentlen = sizeof(uint32_t) + strlen(serve_content);

            comms.datalen = htonl(contentlen);
            comms.data = (uint8_t*)serve_content;

            valwrite = write(connfd, &comms, contentlen);

            if(valwrite <= 0){

                fprintf(stderr,"write: %d\n", valwrite);

            }
        }

        int keepalive = 1;

        comms.datalen = 0;
        comms.data = NULL;
        uint32_t rhead = 0;

        while(keepalive){


            int valread = 0;

            while(valread < sizeof(uint32_t)){

                int rb = read(connfd, &rhead + valread, sizeof(uint32_t) - valread);

                if (rb <= 0){

                    keepalive = 0;
                    break;

                } 

                valread += rb;

            }

            comms.datalen = ntohl(rhead);

            comms.data = (uint8_t*)malloc(comms.datalen);

            valread = 0;

            while(valread < comms.datalen){

                int rb = read(connfd, &comms.data + valread, comms.datalen - valread);

                if (rb <= 0){

                    free(comms.data);

                    keepalive = 0;
                    break;

                } 

                valread += rb;

            }

            fprintf(stdout, "%s\n", comms.data);

            free(comms.data);

        }

        close(connfd);

    }

    close(sockfd);

    return 0;
}



void* NCAT_get_thread(){

    if(ncat_opts.mode_client){

        NCAT_COMMS comms;

        memset(&comms, 0, sizeof(NCAT_COMMS));

        for(;;){

            if(ncat_opts._client_sock_ready){

                int valread = 0;

                uint8_t rhead = 0;

                int _exit_prog=0;
                
                while(valread < sizeof(uint32_t)){

                    int rb = read(ncat_opts._client_sockfd, &rhead + valread, sizeof(uint32_t) - valread);

                    if(rb <= 0){
                        
                        _exit_prog = 1;

                        break;

                    }

                    valread += rb;
                }
               
                comms.datalen = ntohl(rhead);

                comms.data = (uint8_t*)malloc(comms.datalen);

                valread = 0;

                while(valread < comms.datalen){

                    int rb = read(ncat_opts._client_sockfd, &comms.data + valread, comms.datalen - valread);

                    if(rb <= 0){
                        
                        _exit_prog = 1;

                        free(comms.data);

                        break;

                    }

                    valread += rb;
                }

                fprintf(stdout, "%s \n", comms.data);

                free(comms.data);
                

            } else {
                
                msleep(100);

            }


        }


    } else if (ncat_opts.mode_listen){

        struct pollfd sig_wait = {.fd = STDIN_FILENO, .events = POLLIN};

        int chunk = 1;

        int content_len = 0;

        serve_content = (char*)malloc(INPUT_BUFF_CHUNK * chunk);

        memset(serve_content, 0, INPUT_BUFF_CHUNK * chunk);

        char* content_ptr = serve_content + content_len;

        char c = 0;

        for(int count = 0; count < 1; count++){

            switch(poll(&sig_wait, 1, SERVER_SIG_TIMEOUT_MS)){

                case 1:
                    
                    while((c = fgetc(stdin)) != EOF){


                        *content_ptr = c; 
            
                        content_len += 1;
            
                        if(content_len == (INPUT_BUFF_CHUNK * chunk)){
            
                            chunk += 1;
            
                            serve_content = (char*)realloc(serve_content, INPUT_BUFF_CHUNK * chunk);
            
                        }
            
                        content_ptr = serve_content + content_len;
                        
                    }
        
                default:

                    count += 1;

            }

        }

        if(content_len != 0){
            printf("loaded server text: \n%s\n", serve_content);
            write(ncat_opts._server_sig[1], SERVER_SIG_DONE, SERVER_SIG_LEN);
        }

    }

    pthread_exit(NULL);

}


void msleep(long ms){

    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;

    nanosleep(&ts, &ts);
}