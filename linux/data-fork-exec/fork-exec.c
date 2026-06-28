#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
int val = 0;


void* rrr(void* varg){
	val = 5;
	pthread_exit(NULL);
}

int main( void ) {
	char *argv[1] = {NULL};

    printf( "parent process pid: %d\n", (int)getpid() );


	int pid = fork();

	if ( pid == 0 ) {
		// for new session
		// signal effective
		// setsid();
		pthread_t tid;
		pthread_create(&tid, NULL, rrr, NULL);
		pthread_join(tid, NULL);
        printf( "child process pid: %d: val: %d\n", (int)getpid(), val);
		execvp( "ls", argv );
	}

	sleep(2);

	printf( "child pid: %d\n", pid);
	printf( "parent process pid: %d: val: %d\n", (int)getpid(), val);

	return 0;
}