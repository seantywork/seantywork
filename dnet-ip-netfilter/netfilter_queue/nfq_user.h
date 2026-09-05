#ifndef _NFQ_USER_H_
#define _NFQ_USER_H_

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
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/random.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
 #include <ifaddrs.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>	
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

//#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/rtnetlink.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <xdp/prog_dispatcher.h>

#define DEFAULT_NUM_FRAME_SIZE 0xFFFF + ((sysconf(_SC_PAGESIZE) < 8192L ? sysconf(_SC_PAGESIZE) : 8192L)/2)
#define DEFAULT_RECV_FRAME_SIZE 8192 * 2600 * 2
#define DEFAULT_VERDICT NF_DROP

#define MAX_THREADS 8
#define IFLEFT "veth11"
#define IFRIGHT "veth21"
#define BRNAME "vbr0"
#define XDPPROGNAME "xdpprog.o"
#define XDPMAPNAME "inline_hw_tg"
#define XDPMAPKEY 0

struct thread_data {
    pthread_t tid;
    int queuenum;
    int ctxid;
};

struct hwaddr {
  uint8_t data[6];
  uint8_t rsvd[2];
};

extern struct thread_data threads[MAX_THREADS];
extern int keepalive;
extern struct xdp_program *prog_l;
extern struct xdp_program *prog_r;
extern int map_fd_l;
extern int map_fd_r;
extern struct hwaddr hwaddr;
#endif 