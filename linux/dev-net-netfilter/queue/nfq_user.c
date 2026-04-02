#include "nfq_user.h"


struct thread_data threads[MAX_THREADS];
int keepalive = 1;
struct xdp_program *prog_l = NULL;
struct xdp_program *prog_r = NULL;
int map_fd_l;
int map_fd_r;
struct hwaddr hwaddr;

void ch_handler(int sig){
    printf("sig received %d\n", sig);
    keepalive = 0;
}

int process_packet(int ctx_id, int* verdict, void* data, int datalen){

    return 0;
};

uint32_t set_verdict(int ctx_id, int* verdict, struct nfq_data *tb){
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	uint8_t *dataraw;
    int v = DEFAULT_VERDICT;
	int datalen;
    void *data;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	} else {
		*verdict = -1;
		return id;
	}
	ret = nfq_get_payload(tb, &dataraw);
	if(ret < 0){
		*verdict = -2;
		return id;
	}
	datalen = ret;
	data = (void*)(long)dataraw;
    if(process_packet(ctx_id, verdict, data, datalen) < 0){
        printf("failed flow controller query\n");
        *verdict = -3;
        return id;
    }
	return id;
}


int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	uint32_t id;
	int verdict;
	int* qid_ptr = (int*)data;
	int qid = *qid_ptr;
	int ctx_id = qid;
	id = set_verdict(ctx_id, &verdict, nfa);
	if(verdict < 0){
		printf("failed to process packet: %d\n", verdict);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}


void* nfq_thread(void* varg){
	int* ctx_id_ptr = (int*)varg;
	int ctx_id = *ctx_id_ptr;
	printf("run ctx: %d\n", ctx_id);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[DEFAULT_NUM_FRAME_SIZE] __attribute__ ((aligned));

	printf("raw msg buff size: %d\n", DEFAULT_NUM_FRAME_SIZE);
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		return (void*)EXIT_FAILURE;
	}
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		return (void*)EXIT_FAILURE;
	}
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		return (void*)EXIT_FAILURE;
	}
	printf("binding this socket to queue '%d'\n", threads[ctx_id].queuenum);
	qh = nfq_create_queue(h, threads[ctx_id].queuenum, nfq_cb, &threads[ctx_id].queuenum);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		return (void*)EXIT_FAILURE;
	}
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		return (void*)EXIT_FAILURE;
	}
	fd = nfq_fd(h);
	int opt = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
	//thread_data_nfq[ctx_id].fd = fd;
	//thread_data_nfq[ctx_id].h = h;
	//thread_data_nfq[ctx_id].qh = qh;
	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		nfq_handle_packet(h, buf, rv);
	}
	printf("exit nfq run ctx: %d\n", ctx_id);
	nfq_destroy_queue(qh);
	nfq_close(h);
#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	
	/*
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
	*/
#endif
	return (void*)EXIT_SUCCESS;
}


int load_xdp_prog(){
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts_l);
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts_r);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts_l, 0);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts_r, 0);
    struct bpf_map *map_l;
    struct bpf_map *map_r;
    char errmsg[1024];
    int left_ifindex = if_nametoindex(IFLEFT);
    printf("left iface name: %s\n", IFLEFT);
    int right_ifindex = if_nametoindex(IFRIGHT);
    printf("right iface name: %s\n", IFRIGHT);
    printf("attaching custom progs to interfaces\n");
    xdp_opts_l.open_filename = XDPPROGNAME;
    //xdp_opts.prog_name = _left_progname;
    xdp_opts_l.opts = &opts_l;
    xdp_opts_r.open_filename = XDPPROGNAME;
    //xdp_opts_r.prog_name = _right_progname;
    xdp_opts_r.opts = &opts_r;

    prog_l = xdp_program__open_file(XDPPROGNAME, NULL, &opts_l);
    printf("xdp opened left file\n");
    prog_r = xdp_program__open_file(XDPPROGNAME, NULL, &opts_r);
    printf("xdp opened right file\n");
    long err = libxdp_get_error(prog_l);
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
    err = xdp_program__attach(prog_l, left_ifindex, XDP_MODE_UNSPEC, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        printf("Couldn't attach XDP program on iface '%d' : %s (%d)\n",
            left_ifindex, errmsg, err);
        return err;
    }
    err = xdp_program__attach(prog_r, right_ifindex, XDP_MODE_UNSPEC, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        printf("Couldn't attach XDP program on iface '%d' : %s (%d)\n",
            right_ifindex, errmsg, err);
        return err;
    }
    map_l = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog_l), XDPMAPNAME);
    map_fd_l = bpf_map__fd(map_l);
    if (map_fd_l < 0) {
        printf("ERROR: no map found on left: %s\n",
            strerror(map_fd_l));
        return err;
    }
    map_r = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog_r), XDPMAPNAME);
    map_fd_r = bpf_map__fd(map_r);
    if (map_fd_l < 0) {
        printf("ERROR: no map found on right: %s\n",
            strerror(map_fd_r));
        return err;
    }
    return 0;
}

int set_xdp_prog_info(){
    struct ifreq ifr;
    int key = XDPMAPKEY;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd < 0) {
        printf("tmp arp socket failed\n");
        return -1;
    }
    strncpy(ifr.ifr_name, BRNAME, IFNAMSIZ - 1);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        printf("tmp arp socket ifindex failed\n");
        close(sd);
        return -1;
    }
    printf("interface index is %d\n", ifr.ifr_ifindex);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        printf("tmp arp socket hwaddr get failed\n");
        close(sd);
        return -1;
    }
    memcpy(hwaddr.data, ifr.ifr_hwaddr.sa_data, 6);
    close(sd);
    int updated = bpf_map_update_elem(map_fd_l, &key, &hwaddr, BPF_ANY);
    if(updated != 0){
        printf("prog update failed: left\n");
        return -1;
    }
    updated = bpf_map_update_elem(map_fd_r, &key, &hwaddr, BPF_ANY);
    if(updated != 0){
        printf("prog update failed: right\n");
        return -1;
    }
    return 0;
}

void unload_xdp_prog(){
    struct xdp_multiprog *mp;
    int err;
    mp = xdp_multiprog__get_from_ifindex(if_nametoindex(IFLEFT));
    if (!mp) {
        printf("No XDP program loaded on %s\n", IFLEFT);
    } else {
        err = xdp_multiprog__detach(mp);
        if (err){
            printf("Unable to detach XDP program: %s\n", strerror(-err));
        }
                
    }
    mp = xdp_multiprog__get_from_ifindex(if_nametoindex(IFRIGHT));
    if (!mp) {
        printf("No XDP program loaded on %s\n", IFRIGHT);
    } else {
        err = xdp_multiprog__detach(mp);
        if (err){
            printf("Unable to detach XDP program: %s\n", strerror(-err));
        }
                
    }
}

int main(){

    char cmdbuf[1024];
    int startqnum = 100;
    int endqnum = startqnum + MAX_THREADS - 1;
    signal(SIGINT, ch_handler);
    printf("adding iptable rules...\n");
    system("iptables -F");
    sprintf(cmdbuf, "iptables -I FORWARD -p all -o %s -j NFQUEUE --queue-balance %d:%d", BRNAME, startqnum, endqnum);
    system(cmdbuf);
    memset(cmdbuf, 0, 1024);
    sprintf(cmdbuf, "iptables -I FORWARD -p all -i %s -j NFQUEUE --queue-balance %d:%d", BRNAME, startqnum, endqnum);
    system(cmdbuf);
    memset(cmdbuf, 0, 1024);
    printf("added all rules\n");
    printf("creating threads..\n");
    for(int i = 0; i < MAX_THREADS; i++){
        int qnum = startqnum + i;
        threads[i].queuenum = qnum;
        threads[i].ctxid = i;
        pthread_create(&threads[i].tid, NULL, nfq_thread, (void*)&threads[i].ctxid);
    }
    printf("created all threads\n");
    printf("loading xdp programs...\n");
    if(load_xdp_prog(XDPPROGNAME, XDPPROGNAME) < 0){
        printf("failed to load xdp prog\n");
        goto out;
    }
    printf("loaded all xdp programs\n");
    printf("setting xdp program data...\n");
    if(set_xdp_prog_info(map_fd_l) < 0){
        printf("failed to load xdp prog left\n");
        goto out;
    }
    if(set_xdp_prog_info(map_fd_r) < 0){
        printf("failed to load xdp prog right\n");
        goto out;
    }
    printf("set all xdp program data\n");

    while(keepalive){
        sleep(1);
    }
out:
    system("iptables -F");
    unload_xdp_prog();
    return 0;
}