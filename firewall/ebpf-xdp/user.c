


#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <net/if.h>


#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

char* ifname = "veth02";
char* filename = "prog/firewall.o";
char* mapname = "port_verdict";
int map_fd = 0;

enum xdp_attach_mode attach_mode = 0;


static void remove_xdp_program(void)
{
	struct xdp_multiprog *mp;
	int i, err;

    mp = xdp_multiprog__get_from_ifindex(if_nametoindex(ifname));

    if (!mp) {
        printf("no xdp program loaded on %s\n", ifname);
        return;
    }

    err = xdp_multiprog__detach(mp);
    if (err){
        printf("unable to detach xdp program: %s\n", strerror(-err));
    }

}


int main(int argc, char **argv){

    int err;
    char errmsg[1024];

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

    struct xdp_program *prog;
    struct bpf_map *map;

    xdp_opts.open_filename = filename;
    xdp_opts.opts = &opts;

    int ifindex = if_nametoindex(ifname);

	prog = xdp_program__open_file(filename, NULL, &opts);

	err = xdp_program__attach(prog, ifindex, attach_mode, 0);

	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		printf("failed to attach XDP program on iface '%d' : %s (%d)\n", ifindex, errmsg, err);
		return err;
	}

    int retid = 0;
    int sid = 0;
    int mid = 0;

    while(1){

        retid = bpf_map_get_next_id(sid, &mid);

        if(retid < 0){
            break;
        }

        struct bpf_map_info minfo;

        memset(&minfo, 0, sizeof(struct bpf_map_info));

        unsigned int minfo_len = sizeof(struct bpf_map_info);

        int mapfd = bpf_map_get_fd_by_id(mid);

        retid = bpf_map_get_info_by_fd(mapfd, &minfo, &minfo_len);

        if(retid < 0){
            break;
        }

        if(strcmp(minfo.name, mapname) == 0){
            
            printf("fd: %d name: %s\n", mapfd, minfo.name);
                
            map_fd = mapfd;


        } else {
            printf("map name not matched: %s\n", minfo.name);
        }

        sid = mid;
    }

    printf("updating map: dropping packets with tcp dest port 9999\n");

    uint16_t port = 9999;

    uint16_t verdict = 0;

    int result = bpf_map_update_elem(map_fd, &port, &verdict, BPF_ANY);

    if(result != 0){

        printf("failed to update map: %d\n", result);

        return -1;
    }

    verdict = -1;

    bpf_map_lookup_elem(map_fd, &port, &verdict);

    printf("verdict retrieved: %d\n", verdict);

    int quit = 0;

    while(quit == 0){

        char cmd[1024] = {0};

        printf("Enter 'r' to reverse rule, or 'q' to exit: ");

        fgets(cmd, 1024, stdin);

        for(int i = 0 ; i < 1024; i++){

            if(cmd[i] == 'r'){

                if(verdict == 1){
                    verdict = 0;
                } else {
                    verdict = 1;
                }

                result = bpf_map_update_elem(map_fd, &port, &verdict, BPF_ANY);

                if(result != 0){
            
                    printf("failed to update map: %d\n", result);
            
                    goto END;
                }
            
                verdict = -1;
            
                bpf_map_lookup_elem(map_fd, &port, &verdict);
            
                printf("verdict retrieved: %d\n", verdict);
                
                break;

            } else if(cmd[i] == 'q'){

                quit = 1;

                break;
            }

        }


    }

END:

    remove_xdp_program();

    return 0;
}