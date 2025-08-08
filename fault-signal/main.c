#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>


int counter = 0;

void ch_handler(int sig){
    struct tm tm_info;
    char timebuf[128] = {0};
    time_t ch_timer = time(NULL);
    printf("sig received %d: %d\n", sig, counter);
	localtime_r(&ch_timer, &tm_info);
	strftime(timebuf, 128, "%Y-%m-%d %H:%M:%S", &tm_info);
	printf("[%s] signal handled: %d\n", timebuf, counter);
}


int main(int argc, char** argv){

	time_t timer;
	struct tm tm_info;
    pthread_t tid;
	char timebuf[128] = {0};

	signal(SIGINT, ch_handler);
	while(1){
        timer = time(NULL);
		localtime_r(&timer, &tm_info);
        strftime(timebuf, 128, "%Y-%m-%d %H:%M:%S", &tm_info);
        counter += 1;
        if(counter % 100 == 0){
            printf("[%s] counting: %d\n", timebuf, counter);
        }
	}

	return 0;
}
