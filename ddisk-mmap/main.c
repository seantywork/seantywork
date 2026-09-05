#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h> /* mmap() is defined in this header */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* Many POSIX functions (but not all, by a large margin) */
#include <fcntl.h> 


int main (int argc, char *argv[]){
    int fdin, fdout;
    char *src, *dst;
    struct stat statbuf;

    if ((fdin = open ("in.txt", O_RDONLY)) < 0){
        printf("can't open %s for reading", argv[1]);
        return 0;   
    }

    if ((fdout = open ("out.txt", O_RDWR | O_CREAT | O_TRUNC, 0777 )) < 0){
        printf ("can't create %s for writing", argv[2]);
        return 0;
    }

    if (fstat (fdin,&statbuf) < 0){
        printf ("fstat error");
        return 0;
    }

    if (lseek (fdout, statbuf.st_size - 1, SEEK_SET) == -1){
        printf ("lseek error");
        return 0;
    }
 
 
    if (write (fdout, "", 1) != 1){
        printf ("write error");
        return 0;
    }

    if ((src = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0))== MAP_FAILED){
        printf ("mmap error for input");
        return 0;
    }

    if ((dst = mmap (0, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0)) == MAP_FAILED){
        printf ("mmap error for output");
        return 0;
    }
    memcpy (dst, src, statbuf.st_size);

    munmap(src, statbuf.st_size);
    munmap(dst, statbuf.st_size);

    return 0;

}   