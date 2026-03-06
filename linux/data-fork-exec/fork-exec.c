#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main( void ) {
	char *argv[1] = {NULL};

    printf( "parent process pid: %d\n", (int)getpid() );


	int pid = fork();

	if ( pid == 0 ) {
		// for new session
		// signal effective
		// setsid();

        printf( "child process pid: %d\n", (int)getpid() );
		execvp( "ls", argv );
	}

	sleep(2);

	printf( "child pid: %d\n", pid);
	printf( "parent process pid: %d\n", (int)getpid() );

	return 0;
}