#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
int val = 0;


void* rrr(void* varg){
	val = 5;
	pthread_exit(NULL);
}

int main(int argc, char** argv) {
	char *argv2[1] = {NULL};
    printf( "parent process pid: %d\n", (int)getpid() );
	int pid = fork();

	if ( pid == 0 ) {
		// for new session
		// signal effective
		// setsid();
		pthread_t tid;
		int* fault = NULL;
		if(argc > 1){
			printf("here comes the fault\n");
			fault[10] = 1;
		} else {
			pthread_create(&tid, NULL, rrr, NULL);
			pthread_join(tid, NULL);
			printf("child process pid: %d: val: %d\n", (int)getpid(), val);
			execvp("ls", argv2);
		}
	} else {
		int status = 0;
		wait(&status);
		if(WIFEXITED(status)){
			printf("exited, status=%d\n", WEXITSTATUS(status));
		} else if(WIFSIGNALED(status)){
			printf("killed by signal %d\n", WTERMSIG(status));
		} else if(WIFSTOPPED(status)){
			printf("stopped by signal %d\n", WSTOPSIG(status));
		} else if(WIFCONTINUED(status)){
			printf("continued\n");
		}
	}

	printf( "child pid: %d\n", pid);
	printf( "parent process pid: %d: val: %d\n", (int)getpid(), val);

	return 0;
}