#include "af-rxtx.h"


struct bpool *bpool_init(struct bpool_params *params,
	   struct xsk_umem_config *umem_cfg)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	u64 n_slabs, n_slabs_reserved, n_buffers, n_buffers_reserved;
	u64 slabs_size, slabs_reserved_size;
	u64 buffers_size, buffers_reserved_size;
	u64 total_size, i;
	struct bpool *bp;
	u8 *p;
	int status;

	/* mmap prep. */
	if (setrlimit(RLIMIT_MEMLOCK, &r))
		return NULL;

	/* bpool internals dimensioning. */
	n_slabs = (params->n_buffers + params->n_buffers_per_slab - 1) /
		params->n_buffers_per_slab;
	n_slabs_reserved = params->n_users_max * 2;
	n_buffers = n_slabs * params->n_buffers_per_slab;
	n_buffers_reserved = n_slabs_reserved * params->n_buffers_per_slab;

	slabs_size = n_slabs * sizeof(u64 *);
	slabs_reserved_size = n_slabs_reserved * sizeof(u64 *);
	buffers_size = n_buffers * sizeof(u64);
	buffers_reserved_size = n_buffers_reserved * sizeof(u64);

	total_size = sizeof(struct bpool) +
		slabs_size + slabs_reserved_size +
		buffers_size + buffers_reserved_size;

	/* bpool memory allocation. */
	p = calloc(total_size, sizeof(u8));
	if (!p)
		return NULL;

	/* bpool memory initialization. */
	bp = (struct bpool *)p;
	memcpy(&bp->params, params, sizeof(*params));
	bp->params.n_buffers = n_buffers;

	bp->slabs = (u64 **)&p[sizeof(struct bpool)];
	bp->slabs_reserved = (u64 **)&p[sizeof(struct bpool) +
		slabs_size];
	bp->buffers = (u64 *)&p[sizeof(struct bpool) +
		slabs_size + slabs_reserved_size];
	bp->buffers_reserved = (u64 *)&p[sizeof(struct bpool) +
		slabs_size + slabs_reserved_size + buffers_size];

	bp->n_slabs = n_slabs;
	bp->n_slabs_reserved = n_slabs_reserved;
	bp->n_buffers = n_buffers;

	for (i = 0; i < n_slabs; i++)
		bp->slabs[i] = &bp->buffers[i * params->n_buffers_per_slab];
	bp->n_slabs_available = n_slabs;

	for (i = 0; i < n_slabs_reserved; i++)
		bp->slabs_reserved[i] = &bp->buffers_reserved[i *
			params->n_buffers_per_slab];
	bp->n_slabs_reserved_available = n_slabs_reserved;

	for (i = 0; i < n_buffers; i++)
		bp->buffers[i] = i * params->buffer_size;

	/* lock. */
	status = pthread_mutex_init(&bp->lock, NULL);
	if (status) {
		free(p);
		return NULL;
	}

	/* mmap. */
	bp->addr = mmap(NULL,
			n_buffers * params->buffer_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | params->mmap_flags,
			-1,
			0);
	if (bp->addr == MAP_FAILED) {
		pthread_mutex_destroy(&bp->lock);
		free(p);
		return NULL;
	}

	/* umem. */
	status = xsk_umem__create(&bp->umem,
				  bp->addr,
				  bp->params.n_buffers * bp->params.buffer_size,
				  &bp->umem_fq,
				  &bp->umem_cq,
				  umem_cfg);
	if (status) {
		munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
		pthread_mutex_destroy(&bp->lock);
		free(p);
		return NULL;
	}
	memcpy(&bp->umem_cfg, umem_cfg, sizeof(*umem_cfg));

	return bp;
}


void bpool_free(struct bpool *bp)
{
	if (!bp)
		return;

	xsk_umem__delete(bp->umem);
	munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
	pthread_mutex_destroy(&bp->lock);
	free(bp);
}

u32 bcache_slab_size(struct bcache *bc)
{
	struct bpool *bp = bc->bp;

	return bp->params.n_buffers_per_slab;
}

struct bcache *bcache_init(struct bpool *bp)
{
	struct bcache *bc;

	bc = calloc(1, sizeof(struct bcache));
	if (!bc)
		return NULL;

	bc->bp = bp;
	bc->n_buffers_cons = 0;
	bc->n_buffers_prod = 0;

	pthread_mutex_lock(&bp->lock);
	if (bp->n_slabs_reserved_available == 0) {
		pthread_mutex_unlock(&bp->lock);
		free(bc);
		return NULL;
	}

	bc->slab_cons = bp->slabs_reserved[bp->n_slabs_reserved_available - 1];
	bc->slab_prod = bp->slabs_reserved[bp->n_slabs_reserved_available - 2];
	bp->n_slabs_reserved_available -= 2;
	pthread_mutex_unlock(&bp->lock);

	return bc;
}

void bcache_free(struct bcache *bc)
{
	struct bpool *bp;

	if (!bc)
		return;

	/* In order to keep this example simple, the case of freeing any
	 * existing buffers from the cache back to the pool is ignored.
	 */

	bp = bc->bp;
	pthread_mutex_lock(&bp->lock);
	bp->slabs_reserved[bp->n_slabs_reserved_available] = bc->slab_prod;
	bp->slabs_reserved[bp->n_slabs_reserved_available + 1] = bc->slab_cons;
	bp->n_slabs_reserved_available += 2;
	pthread_mutex_unlock(&bp->lock);

	free(bc);
}

u32 bcache_cons_check(struct bcache *bc, u32 n_buffers)
{
	struct bpool *bp = bc->bp;
	u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
	u64 n_buffers_cons = bc->n_buffers_cons;
	u64 n_slabs_available;
	u64 *slab_full;

	/*
	 * Consumer slab is not empty: Use what's available locally. Do not
	 * look for more buffers from the pool when the ask can only be
	 * partially satisfied.
	 */
	if (n_buffers_cons)
		return (n_buffers_cons < n_buffers) ?
			n_buffers_cons :
			n_buffers;

	/*
	 * Consumer slab is empty: look to trade the current consumer slab
	 * (full) for a full slab from the pool, if any is available.
	 */
	pthread_mutex_lock(&bp->lock);
	n_slabs_available = bp->n_slabs_available;
	if (!n_slabs_available) {
		pthread_mutex_unlock(&bp->lock);
		return 0;
	}

	n_slabs_available--;
	slab_full = bp->slabs[n_slabs_available];
	bp->slabs[n_slabs_available] = bc->slab_cons;
	bp->n_slabs_available = n_slabs_available;
	pthread_mutex_unlock(&bp->lock);

	bc->slab_cons = slab_full;
	bc->n_buffers_cons = n_buffers_per_slab;
	return n_buffers;
}

u64 bcache_cons(struct bcache *bc)
{
	u64 n_buffers_cons = bc->n_buffers_cons - 1;
	u64 buffer;

	buffer = bc->slab_cons[n_buffers_cons];
	bc->n_buffers_cons = n_buffers_cons;
	return buffer;
}

void bcache_prod(struct bcache *bc, u64 buffer)
{
	struct bpool *bp = bc->bp;
	u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
	u64 n_buffers_prod = bc->n_buffers_prod;
	u64 n_slabs_available;
	u64 *slab_empty;

	/*
	 * Producer slab is not yet full: store the current buffer to it.
	 */
	if (n_buffers_prod < n_buffers_per_slab) {
		bc->slab_prod[n_buffers_prod] = buffer;
		bc->n_buffers_prod = n_buffers_prod + 1;
		return;
	}

	/*
	 * Producer slab is full: trade the cache's current producer slab
	 * (full) for an empty slab from the pool, then store the current
	 * buffer to the new producer slab. As one full slab exists in the
	 * cache, it is guaranteed that there is at least one empty slab
	 * available in the pool.
	 */
	pthread_mutex_lock(&bp->lock);
	n_slabs_available = bp->n_slabs_available;
	slab_empty = bp->slabs[n_slabs_available];
	bp->slabs[n_slabs_available] = bc->slab_prod;
	bp->n_slabs_available = n_slabs_available + 1;
	pthread_mutex_unlock(&bp->lock);

	slab_empty[0] = buffer;
	bc->slab_prod = slab_empty;
	bc->n_buffers_prod = 1;
}


void port_free(struct port *p)
{
	if (!p)
		return;

	/* To keep this example simple, the code to free the buffers from the
	 * socket's receive and transmit queues, as well as from the UMEM fill
	 * and completion queues, is not included.
	 */

	if (p->xsk)
		xsk_socket__delete(p->xsk);

	bcache_free(p->bc);

	free(p);
}

struct port *port_init(struct port_params *params)
{
	struct port *p;
	u32 umem_fq_size, pos = 0;
	int status, i;

	/* Memory allocation and initialization. */
	p = calloc(sizeof(struct port), 1);
	if (!p)
		return NULL;

	memcpy(&p->params, params, sizeof(p->params));
	umem_fq_size = params->bp->umem_cfg.fill_size / BPOOL_GRP;

	/* bcache. */
	p->bc = bcache_init(params->bp);
	if (!p->bc ||
	    (bcache_slab_size(p->bc) < umem_fq_size) ||
	    (bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size)) {
		port_free(p);
		return NULL;
	}

	params->xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	printf("set: libxdp_falgs: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD\n");
	params->xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP;
	printf("set: bind_flags: XDP_USE_NEED_WAKEUP\n");

	/* xsk socket. */
	status = xsk_socket__create_shared(&p->xsk,
					   params->iface,
					   params->iface_queue,
					   params->bp->umem,
					   &p->rxq,
					   &p->txq,
					   &p->umem_fq,
					   &p->umem_cq,
					   &params->xsk_cfg);
	if (status) {
		port_free(p);
		return NULL;
	}

	if(lr_count % 2 == 0){
		status = xsk_socket__update_xskmap(p->xsk, xsk_map_fd_l);
		lr_count += 1;
	} else {
		status = xsk_socket__update_xskmap(p->xsk, xsk_map_fd_r);
		lr_count += 1;
	}

	if(status){
		printf("failed to update xskmap: lr_count: %d\n", lr_count);
		return NULL;
	} 

	/* umem fq. */
	xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);

	for (i = 0; i < umem_fq_size; i++)
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
			bcache_cons(p->bc);

	xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
	p->umem_fq_initialized = 1;

	return p;
}

u32 port_rx_burst(struct port *p, struct burst_rx *b)
{
	u32 n_pkts, pos, i;

	/* Free buffers for FQ replenish. */
	n_pkts = ARRAY_SIZE(b->addr);

	n_pkts = bcache_cons_check(p->bc, n_pkts);
	if (!n_pkts)
		return 0;

	/* RXQ. */
	n_pkts = xsk_ring_cons__peek(&p->rxq, n_pkts, &pos);
	if (!n_pkts) {
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
			struct pollfd pollfd = {
				.fd = xsk_socket__fd(p->xsk),
				.events = POLLIN,
			};

			poll(&pollfd, 1, 0);
		}
		return 0;
	}

	for (i = 0; i < n_pkts; i++) {
		b->addr[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->addr;
		b->len[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->len;
	}

	xsk_ring_cons__release(&p->rxq, n_pkts);
	p->n_pkts_rx += n_pkts;

	/* UMEM FQ. */
	for ( ; ; ) {
		int status;

		status = xsk_ring_prod__reserve(&p->umem_fq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
			struct pollfd pollfd = {
				.fd = xsk_socket__fd(p->xsk),
				.events = POLLIN,
			};

			poll(&pollfd, 1, 0);
		}
	}

	for (i = 0; i < n_pkts; i++)
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
			bcache_cons(p->bc);

	xsk_ring_prod__submit(&p->umem_fq, n_pkts);

	return n_pkts;
}

void port_tx_burst(struct port *p, struct burst_tx *b)
{
	u32 n_pkts, pos, i;
	int status;


	/* TXQ. */
	n_pkts = b->n_pkts;

	for ( ; ; ) {
		status = xsk_ring_prod__reserve(&p->txq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->txq))
			sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT,
			       NULL, 0);
	}

	for (i = 0; i < n_pkts; i++) {
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->addr = b->addr[i];
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->len = b->len[i];
	}

	xsk_ring_prod__submit(&p->txq, n_pkts);
	if (xsk_ring_prod__needs_wakeup(&p->txq))
		sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	p->n_pkts_tx += n_pkts;


	/* UMEM CQ. */
	n_pkts = p->params.bp->umem_cfg.comp_size;

	n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);

	for (i = 0; i < n_pkts; i++) {
		u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);

		bcache_prod(p->bc, addr);
	}

	xsk_ring_cons__release(&p->umem_cq, n_pkts);
}



void *thread_func(void *arg)
{
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);

	for (i = 0; !t->quit; i = (i + 1) & (t->n_ports_rx - 1)) {
		struct port *port_rx = t->ports_rx[i];
		struct port *port_tx = t->ports_tx[i];
		struct burst_rx *brx = &t->burst_rx;
		struct burst_tx *btx = &t->burst_tx[i];
		u32 n_pkts, j;

		/* RX. */
		n_pkts = port_rx_burst(port_rx, brx);
		if (!n_pkts)
			continue;
    

		/* Process & TX. */
		for (j = 0; j < n_pkts; j++) {
			u64 addr = xsk_umem__add_offset_to_addr(brx->addr[j]);
			u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr,
						     addr);

			btx->addr[btx->n_pkts] = brx->addr[j];
			btx->len[btx->n_pkts] = brx->len[j];
			btx->n_pkts++;

			if (btx->n_pkts == MAX_BURST_TX) {
				port_tx_burst(port_tx, btx);
				btx->n_pkts = 0;
			}
		}
	}

	return NULL;
}



void *thread_func_poll(void *arg)
{
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	int i, j;
	int done = 0;
	
	if(t->cpu_core_id == -1){

		printf("cpu core id is -1, not locking\n");

	} else {

		printf("cpu core id is %d\n", t->cpu_core_id);

		CPU_ZERO(&cpu_cores);
		CPU_SET(t->cpu_core_id, &cpu_cores);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
		
	}

	struct pollfd* pollfds;

	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 1;

	pollfds = calloc(t->n_ports_rx, sizeof(struct pollfd));

	for(i = 0 ; i < t->n_ports_rx; i ++){

		struct port *port_rx = t->ports_rx[i];

		int sockfd_rx = xsk_socket__fd(port_rx->xsk);
		
		pollfds[i].fd = sockfd_rx;
		pollfds[i].events = POLLIN;

	}


	for(;!t->quit;){

		int n;
		int result;

		n = poll(pollfds, t->n_ports_rx, -1);

		//dbg_printf("poll ready: %d\n", n);
		for(i = 0; i < t->n_ports_rx; i++){

			if(
				(pollfds[i].revents & POLLERR)
				|| (pollfds[i].revents & POLLHUP)
			){

				printf("poll wait error\n");
				continue;
			}


			for(j = 0; j < t->n_ports_rx; j++){

				struct port *port_rx = t->ports_rx[j];
				struct port *port_tx = t->ports_tx[j];
				struct burst_rx *brx = &t->burst_rx;
				struct burst_tx *btx = &t->burst_tx[j];
				u32 n_pkts, k;
				int ret;

				int sockfd = xsk_socket__fd(port_rx->xsk);

				if(pollfds[i].fd == sockfd && (pollfds[i].revents & POLLIN)){

					n_pkts = port_rx_burst(port_rx, brx);
					
					if (!n_pkts)
						continue;


					/* Process & TX. */
					for (k = 0; k < n_pkts; k++) {

						u64 addr = xsk_umem__add_offset_to_addr(brx->addr[k]);
						u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr,
										addr);


						btx->addr[btx->n_pkts] = brx->addr[k];
						btx->len[btx->n_pkts] = brx->len[k];
						btx->n_pkts++;

						if (btx->n_pkts == MAX_BURST_TX) {

							port_tx_burst(port_tx, btx);
							btx->n_pkts = 0;
						}

					}
					

				} else {

					continue;
				}				

			}

		}


	}

	return NULL;
}

void print_usage(char *prog_name)
{
	const char *usage =
		"Usage:\n"
		"\t%s [ -b SIZE ] -c CORE -i INTERFACE [ -q QUEUE ]\n"
		"\n"
		"-c CORE        CPU core to run a packet forwarding thread\n"
		"               on. May be invoked multiple times.\n"
		"\n"
		"-b SIZE        Number of buffers in the buffer pool shared\n"
		"               by all the forwarding threads. Default: %u.\n"
		"\n"
		"-i INTERFACE   Network interface. Each (INTERFACE, QUEUE)\n"
		"               pair specifies one forwarding port. May be\n"
		"               invoked multiple times.\n"
		"\n"
		"-q QUEUE       Network interface queue for RX and TX. Each\n"
		"               (INTERFACE, QUEUE) pair specified one\n"
		"               forwarding port. Default: %u. May be invoked\n"
		"               multiple times.\n"
		"\n";
	printf(usage,
	       prog_name,
	       bpool_params_default.n_buffers,
	       port_params_default.iface_queue);
}

int setup(){

	for(int i = 0; i < g_threads; i++){

		if (n_threads == MAX_THREADS) {
			printf("Max number of threads (%d) reached.\n",
				   MAX_THREADS);
			return -1;
		}

		// no locking

		thread_data[n_threads].cpu_core_id = -1;
		n_threads++;
		g_cpu_core_id_len++;

	}	

	lr_count = 0;

	for (int i  = 0 ; i < g_ports; i++){

		if (n_ports == MAX_PORTS) {
			printf("Max number of ports (%d) reached.\n",
				   MAX_PORTS);
			return -1;
		}

		if(lr_count % 2 == 0){

			port_params[n_ports].iface = left_ifname;
			port_params[n_ports].iface_queue = g_queue_id_len;
			n_ports++;
			lr_count += 1;
		} else {
			port_params[n_ports].iface = right_ifname;
			port_params[n_ports].iface_queue = g_queue_id_len;
			n_ports++;
			lr_count += 1;
			g_queue_id_len++;
		}

	}

	lr_count = 0;

	if (!n_ports) {
		printf("No ports specified.\n");
		return -1;
	}

	if (!n_threads) {
		printf("No threads specified.\n");
		return -1;
	}

	if (n_ports % n_threads) {
		printf("Ports cannot be evenly distributed to threads.\n");
		return -1;
	}

	return 0;
}


void print_port(u32 port_id)
{
	struct port *port = ports[port_id];

	printf("Port %u: interface = %s, queue = %u\n",
	       port_id, port->params.iface, port->params.iface_queue);
}

void print_thread(u32 thread_id)
{
	struct thread_data *t = &thread_data[thread_id];
	u32 i;

	printf("Thread %u (CPU core %u): ",
	       thread_id, t->cpu_core_id);

	for (i = 0; i < t->n_ports_rx; i++) {
		struct port *port_rx = t->ports_rx[i];
		struct port *port_tx = t->ports_tx[i];

		printf("(%s, %u) -> (%s, %u), ",
		       port_rx->params.iface,
		       port_rx->params.iface_queue,
		       port_tx->params.iface,
		       port_tx->params.iface_queue);
	}

	printf("\n");
}

void print_port_stats_separator(void)
{
	printf("+-%4s-+-%12s-+-%13s-+-%12s-+-%13s-+\n",
	       "----",
	       "------------",
	       "-------------",
	       "------------",
	       "-------------");
}


void print_port_stats_header(void)
{
	print_port_stats_separator();
	printf("| %4s | %12s | %13s | %12s | %13s |\n",
	       "Port",
	       "RX packets",
	       "RX rate (pps)",
	       "TX packets",
	       "TX_rate (pps)");
	print_port_stats_separator();
}

void print_port_stats_trailer(void)
{
	print_port_stats_separator();
	printf("\n");
}

void print_port_stats(int port_id, u64 ns_diff)
{
	struct port *p = ports[port_id];
	double rx_pps, tx_pps;

	rx_pps = (p->n_pkts_rx - n_pkts_rx[port_id]) * 1000000000. / ns_diff;
	tx_pps = (p->n_pkts_tx - n_pkts_tx[port_id]) * 1000000000. / ns_diff;

	printf("| %4d | %12llu | %13.0f | %12llu | %13.0f |\n",
	       port_id,
	       p->n_pkts_rx,
	       rx_pps,
	       p->n_pkts_tx,
	       tx_pps);

	n_pkts_rx[port_id] = p->n_pkts_rx;
	n_pkts_tx[port_id] = p->n_pkts_tx;
}

void print_port_stats_all(u64 ns_diff)
{
	int i;

	print_port_stats_header();
	for (i = 0; i < n_ports; i++)
		print_port_stats(i, ns_diff);
	print_port_stats_trailer();
}