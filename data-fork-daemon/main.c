

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <linux/reboot.h>
#include <sys/reboot.h>

#include <pthread.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/wait.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

int main (){


    char* args[] = {"sleep", "10", NULL};

    pid_t dpid = fork();

    if(dpid < 0){

        printf("failed to start daemon");

        exit(EXIT_FAILURE);
    }
    if(dpid == 0){

        setsid();

        signal(SIGINT, SIG_IGN);
 
        execvp(args[0], args);

    } else {

        printf("daemonized pid: %d\n", dpid);

        sleep(1);

        printf("parent exit\n");

        exit(EXIT_SUCCESS);
    }

}