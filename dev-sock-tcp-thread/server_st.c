
#include "server_st.h"


int SERVICE_PORTS[MAX_PORT];

pthread_t TID[MAX_PORT];
pthread_mutex_t TLOCK; 

struct WorkerArg WA[MAX_PORT];

int main() 
{ 


    SERVICE_PORTS[0] = PORT1;
    SERVICE_PORTS[1] = PORT2;
    SERVICE_PORTS[2] = PORT3;

    if(pthread_mutex_init(&TLOCK, NULL) != 0){
        printf("mutex init failed \n");
        return EXIT_FAILURE;
    }


    for(int i = 0; i < MAX_PORT; i++){

        WA[i].WTHREAD_ID = i;
        WA[i].PORT = SERVICE_PORTS[i];

        int perr = pthread_create(&(TID[i]), NULL, Worker, (void *)&(WA[i]));

        if(perr != 0){
            printf("thread creation failed\n");
            return EXIT_FAILURE;
        }else {

            printf("thread created\n");
            
        }

        sleep(1);


    }





    pthread_join(TID[0], NULL);

    pthread_mutex_destroy(&TLOCK);

    return EXIT_SUCCESS;
}


/*
int main() 
{ 

    int main_thread = 10;


    for (int i = 0; i < MAX_CONN; i ++){

        CLIENT_SOCKET[i] = 0;
    }

    SOCKFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (SOCKFD == -1) { 
        printf("socket creation failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else
        printf("socket successfully created\n"); 

    if( setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, (char *)&OPT,  
          sizeof(OPT)) < 0 )   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    }   
     

    bzero(&SERVADDR, sizeof(SERVADDR)); 
   
    SERVADDR.sin_family = AF_INET; 
    SERVADDR.sin_addr.s_addr = htonl(INADDR_ANY); 
    SERVADDR.sin_port = htons(PORT); 
   
    if ((bind(SOCKFD, (SA*)&SERVADDR, sizeof(SERVADDR))) != 0) { 
        printf("socket bind failed\n"); 
        exit(EXIT_FAILURE); 
    } 
   

    if ((listen(SOCKFD, 5)) != 0) { 
        printf("listen failed\n"); 
        exit(EXIT_FAILURE); 
    } 
    else{
        SERVLEN = sizeof(SERVADDR); 
    }

    if(pthread_mutex_init(&TLOCK, NULL) != 0){
        printf("mutex init failed \n");
        return EXIT_FAILURE;
    }




    while(TRUE){

        int new_conn;
        int sock_added = FALSE;
        struct WorkerArg warg;
        int wid;

        printf("waiting for new conn\n");

        new_conn = accept(SOCKFD, (SA* )&SERVADDR, (socklen_t*)&SERVLEN);

        if (new_conn < 0){
    
            printf("accpet error\n");
            exit(EXIT_FAILURE);
        }

        for (int i = 0 ; i < MAX_CONN; i ++){

            if(CLIENT_SOCKET[i] == 0){
                pthread_mutex_lock(&TLOCK);

                CLIENT_SOCKET[i] = new_conn;
                
                warg.WTHREAD_ID = i;
                warg.WSOCK_FD = new_conn;
                
                printf("added new conn\n");
                
                sock_added = TRUE;
                
                pthread_mutex_unlock(&TLOCK);
                
                wid = i;
                
                break;
            }
        }


        int perr = pthread_create(&(TID[wid]), NULL, Worker, (void *)&warg);

        if(perr != 0){
            printf("thread creation failed\n");
            return EXIT_FAILURE;
        }else {

            printf("thread created\n");
            
        }

    }


    pthread_mutex_destroy(&TLOCK);

    return EXIT_SUCCESS;
}

*/