#include "af-rxtx-core.h"
#include "af-rxtx.h"

// number of left, right queue pair
//const int g_threads = 32;
const int g_threads = 4;
int g_ports = g_threads * 2;
int g_cpu_core_id_len = 0;
int g_queue_id_len = 0;
char* left_ifname = "veth01";
char* right_ifname = "veth11";

int lr_count = 0;
struct xdp_program *prog_l;
struct xdp_program *prog_r;
int xsk_map_fd_l;
int xsk_map_fd_r;

char* left_filename = "/bpf/xdp_redirect_xsk.o";
char* right_filename = "/bpf/xdp_redirect_xsk.o";
char* xsk_map_name = "if_redirect";

enum xdp_attach_mode attach_mode = 0;

struct bpool_params bpool_params_default = {
	.n_buffers = XDP_NUM_FRAMES,
	.buffer_size = XDP_FRAME_SIZE,
	.mmap_flags = 0,

	.n_users_max = 16,
	.n_buffers_per_slab = XDP_PROD_RING_NUM * 2,
};

struct xsk_umem_config umem_cfg_default = {
	.fill_size = XDP_PROD_RING_NUM,
	.comp_size = XDP_CONS_RING_NUM,
	.frame_size = XDP_FRAME_SIZE,
	.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	.flags = 0,
};


struct port_params port_params_default = {
	.xsk_cfg = {
		.rx_size = XDP_RX_RING_NUM_DESCS,
		.tx_size = XDP_TX_RING_NUM_DESCS,
		.libxdp_flags = 0,
		.xdp_flags = 0,
		.bind_flags = 0,
//		.xdp_flags = XDP_FLAGS_DRV_MODE,
//		.bind_flags = XDP_USE_NEED_WAKEUP,
	},

	.bp = NULL,
	.iface = NULL,
	.iface_queue = 0,
};



struct bpool_params bpool_params[MAX_BPOOL];
struct xsk_umem_config umem_cfg;
struct bpool **bp;

struct port_params port_params[MAX_PORTS];
struct port *ports[MAX_PORTS];
u64 n_pkts_rx[MAX_PORTS];
u64 n_pkts_tx[MAX_PORTS];
int n_ports;

pthread_t threads[MAX_THREADS];
struct thread_data thread_data[MAX_THREADS];
int n_threads;

int quit;

static void
signal_handler(int sig)
{
	quit = 1;
}

static void remove_xdp_program(void)
{
	struct xdp_multiprog *mp;
	int i, err;

	for (i = 0 ; i < n_ports; i++) {
	        mp = xdp_multiprog__get_from_ifindex(if_nametoindex(port_params[i].iface));
	        if (!mp) {
	        	printf("No XDP program loaded on %s\n", port_params[i].iface);
	        	continue;
	        }

                err = xdp_multiprog__detach(mp);
                if (err)
                        printf("Unable to detach XDP program: %s\n", strerror(-err));
	}
}

int main(int argc, char **argv)
{
	struct timespec time;
	u64 ns0;
	int i;
	int err;
	char errmsg[1024];

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts_l);
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts_r);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts_l, 0);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts_r, 0);

	struct bpf_map *map_l;
	struct bpf_map *map_r;

	for (int i = 0; i < MAX_BPOOL; i++){

		memcpy(&bpool_params[i], &bpool_params_default, sizeof(struct bpool_params));
	}

	bp = (struct bpool**)malloc(sizeof(struct bpool*) * MAX_BPOOL);

	memcpy(&umem_cfg, &umem_cfg_default,
	       sizeof(struct xsk_umem_config));
	for (i = 0; i < MAX_PORTS; i++)
		memcpy(&port_params[i], &port_params_default,
		       sizeof(struct port_params));

	if (setup()) {
		printf("setup failed\n");
		return -1;
	}

	xdp_opts_l.open_filename = left_filename;
	xdp_opts_l.opts = &opts_l;

	xdp_opts_r.open_filename = right_filename;
	xdp_opts_r.opts = &opts_r;


	prog_l = xdp_program__open_file(left_filename, NULL, &opts_l);

	prog_r = xdp_program__open_file(right_filename, NULL, &opts_r);

	err = libxdp_get_error(prog_l);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		printf("ERR: loading program: %s\n", errmsg);
		return err;
	}

	err = libxdp_get_error(prog_r);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		printf("ERR: loading program: re: %s\n", errmsg);
		return err;
	}

	

	int left_ifindex = if_nametoindex(port_params[0].iface);
	printf("left iface name: %s\n",port_params[0].iface);
	int right_ifindex = if_nametoindex(port_params[1].iface);
	printf("right iface name: %s\n",port_params[1].iface);

	err = xdp_program__attach(prog_l, left_ifindex, attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		printf("Couldn't attach XDP program on iface '%d' : %s (%d)\n",
			left_ifindex, errmsg, err);
		return err;
	}

	err = xdp_program__attach(prog_r, right_ifindex, attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		printf("Couldn't attach XDP program on iface '%d' : %s (%d)\n",
			right_ifindex, errmsg, err);
		return err;
	}

	map_l = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog_l), xsk_map_name);
	xsk_map_fd_l = bpf_map__fd(map_l);
	if (xsk_map_fd_l < 0) {
		printf("ERROR: no map found on left: %s\n",
			strerror(xsk_map_fd_l));
		return err;
	}

	map_r = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog_r), xsk_map_name);
	xsk_map_fd_r = bpf_map__fd(map_r);
	if (xsk_map_fd_r < 0) {
		printf("ERROR: no map found on right: %s\n",
			strerror(xsk_map_fd_r));
		return err;
	}


	for(int i = 0 ; i < MAX_BPOOL; i++){

		bp[i] = bpool_init(&bpool_params[i], &umem_cfg);
		if (!bp[i]) {
			printf("Buffer pool initialization failed: %d\n", i);
			return -1;
		}

		printf("bpool done: %d\n", i);

	}

	printf("buffer pool created successfully.\n");

	int bpptr = 0;

	for (i = 0; i < n_ports; i++) {

		if(i != 0){
			if(i % BPOOL_GRP == 0){
				bpptr += 1;
			}
		}

		port_params[i].bp = bp[bpptr];
		
		ports[i] = port_init(&port_params[i]);
		if (!ports[i]) {
			printf("Port %d initialization failed.\n", i);
			return -1;
		}
		print_port(i);
	}
	printf("All ports created successfully.\n");

	/* Threads. */
	for (i = 0; i < n_threads; i++) {
		struct thread_data *t = &thread_data[i];
		u32 n_ports_per_thread = n_ports / n_threads, j;

		for (j = 0; j < n_ports_per_thread; j++) {
			t->ports_rx[j] = ports[i * n_ports_per_thread + j];
			t->ports_tx[j] = ports[i * n_ports_per_thread +
				(j + 1) % n_ports_per_thread];
		}

		t->n_ports_rx = n_ports_per_thread;

		print_thread(i);
	}

	for (i = 0; i < n_threads; i++) {
		int status;

/* no poll
		status = pthread_create(&threads[i],
					NULL,
					thread_func,
					&thread_data[i]);
*/

// CRUCIAL:
//   use poll

		status = pthread_create(&threads[i],
					NULL,
					thread_func_poll,
					&thread_data[i]);
		if (status) {
			printf("Thread %d creation failed.\n", i);
			return -1;
		}
	}
	printf("All threads created successfully.\n");

	/* Print statistics. */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	clock_gettime(CLOCK_MONOTONIC, &time);
	ns0 = time.tv_sec * 1000000000UL + time.tv_nsec;
	for ( ; !quit; ) {
		u64 ns1, ns_diff;

		sleep(1);
		clock_gettime(CLOCK_MONOTONIC, &time);
		ns1 = time.tv_sec * 1000000000UL + time.tv_nsec;
		ns_diff = ns1 - ns0;
		ns0 = ns1;

		print_port_stats_all(ns_diff);
	}

	/* Threads completion. */
	printf("Quit.\n");
	for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);


	bpptr = 0;
	
	for (i = 0; i < n_ports; i++){

		if(i != 0){
			if(i % BPOOL_GRP == 0){
				bpptr += 1;
			}
		}
		port_free(ports[i]);

		bpool_free(bp[bpptr]);
	}

	free(bp);

	remove_xdp_program();

	return 0;
}