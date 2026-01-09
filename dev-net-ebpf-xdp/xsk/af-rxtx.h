#ifndef _AF_RXTX_H_ 
#define _AF_RXTX_H_ 

#include "af-rxtx-core.h"

struct bpool *bpool_init(struct bpool_params *params,
	   struct xsk_umem_config *umem_cfg);

void bpool_free(struct bpool *bp);

u32 bcache_slab_size(struct bcache *bc);

struct bcache *bcache_init(struct bpool *bp);


void bcache_free(struct bcache *bc);


u32 bcache_cons_check(struct bcache *bc, u32 n_buffers);

u64 bcache_cons(struct bcache *bc);

void bcache_prod(struct bcache *bc, u64 buffer);

void port_free(struct port *p);

struct port *port_init(struct port_params *params);

u32 port_rx_burst(struct port *p, struct burst_rx *b);

void port_tx_burst(struct port *p, struct burst_tx *b);


void *thread_func(void *arg);

void *thread_func_poll(void *arg);

void print_usage(char *prog_name);


//int parse_args(int argc, char **argv);

int setup();

void print_port(u32 port_id);

void print_thread(u32 thread_id);

void print_port_stats_separator(void);

void print_port_stats_header(void);

void print_port_stats_trailer(void);

void print_port_stats(int port_id, u64 ns_diff);

void print_port_stats_all(u64 ns_diff);



#endif 