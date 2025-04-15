#ifndef _AF_RXTX_CORE_H_
#define _AF_RXTX_CORE_H_


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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/*
#ifndef MAX_BURST_RX
#define MAX_BURST_RX 64
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 64
#endif
*/
#ifndef MAX_BURST_RX
#define MAX_BURST_RX 1
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 1
#endif

#ifndef MAX_PORTS_PER_THREAD
#define MAX_PORTS_PER_THREAD 16
#endif

#define MAX_BPOOL 32

#define BPOOL_GRP 2

#ifndef MAX_PORTS
#define MAX_PORTS 64
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 32
#endif

#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define XDP_NUM_FRAMES XDP_FRAME_SIZE * 2 * 2 * 2 * 2 
#define XDP_PROD_RING_NUM     XDP_FRAME_SIZE * 2
#define XDP_CONS_RING_NUM     XDP_FRAME_SIZE * 2
#define XDP_RX_RING_NUM_DESCS XDP_FRAME_SIZE * 2
#define XDP_TX_RING_NUM_DESCS XDP_FRAME_SIZE * 2

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

struct bpool_params {
	u32 n_buffers;
	u32 buffer_size;
	int mmap_flags;

	u32 n_users_max;
	u32 n_buffers_per_slab;
};

struct bpool {
	struct bpool_params params;
	pthread_mutex_t lock;
	void *addr;

	u64 **slabs;
	u64 **slabs_reserved;
	u64 *buffers;
	u64 *buffers_reserved;

	u64 n_slabs;
	u64 n_slabs_reserved;
	u64 n_buffers;

	u64 n_slabs_available;
	u64 n_slabs_reserved_available;

	struct xsk_umem_config umem_cfg;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_umem *umem;
};

struct bcache {
	struct bpool *bp;

	u64 *slab_cons;
	u64 *slab_prod;

	u64 n_buffers_cons;
	u64 n_buffers_prod;
};

struct burst_rx {
	u64 addr[MAX_BURST_RX];
	u32 len[MAX_BURST_RX];
};

struct burst_tx {
	u64 addr[MAX_BURST_TX];
	u32 len[MAX_BURST_TX];
	u32 n_pkts;
};

struct port_params {
	struct xsk_socket_config xsk_cfg;
	struct bpool *bp;
	const char *iface;
	u32 iface_queue;
};

struct port {
	struct port_params params;

	struct bcache *bc;

	struct xsk_ring_cons rxq;
	struct xsk_ring_prod txq;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_socket *xsk;
	int umem_fq_initialized;

	u64 n_pkts_rx;
	u64 n_pkts_tx;
};



struct thread_data {
	struct port *ports_rx[MAX_PORTS_PER_THREAD];
	struct port *ports_tx[MAX_PORTS_PER_THREAD];
	u32 n_ports_rx;
	struct burst_rx burst_rx;
	struct burst_tx burst_tx[MAX_PORTS_PER_THREAD];
	u32 cpu_core_id;
	int quit;
};


extern const int g_threads;
extern int g_ports;
extern int g_cpu_core_id_len;
extern int g_queue_id_len;
extern char* left_ifname;
extern char* right_ifname;

extern int lr_count;
extern struct xdp_program *prog_l;
extern struct xdp_program *prog_r;
extern int xsk_map_fd_l;
extern int xsk_map_fd_r;

extern char* left_filename;
extern char* right_filename;

extern char* xsk_map_name;
extern enum xdp_attach_mode attach_mode;

extern struct bpool_params bpool_params_default;

extern struct xsk_umem_config umem_cfg_default;

extern struct port_params port_params_default;



extern struct bpool_params bpool_params[MAX_BPOOL];
extern struct xsk_umem_config umem_cfg;
extern struct bpool **bp;

extern struct port_params port_params[MAX_PORTS];
extern struct port *ports[MAX_PORTS];
extern u64 n_pkts_rx[MAX_PORTS];
extern u64 n_pkts_tx[MAX_PORTS];
extern int n_ports;

extern pthread_t threads[MAX_THREADS];
extern struct thread_data thread_data[MAX_THREADS];
extern int n_threads;

extern int quit;





#endif