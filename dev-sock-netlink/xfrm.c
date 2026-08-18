#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include <pthread.h>

#include <linux/rtnetlink.h>
#include <linux/xfrm.h>


#define NETLINK_REQ_DATA_SIZE 8192

#define NL_XFRM_REQ struct { \
		    struct nlmsghdr n; \
		    struct xfrm_usersa_id id; \
	    }

int keep_alive = 1;
int nl_send_fd = -1;
int netlink_xfrm_fd = -1;

struct nlm_resp {
	struct nlmsghdr n;
	union {
		struct nlmsgerr e;
		struct xfrm_userpolicy_info pol;        /* netlink_policy_expire */
		struct xfrm_usersa_info sa;     /* netlink_get_spi */
		struct xfrm_usersa_info info;   /* netlink_get_sa */
		char data[NETLINK_REQ_DATA_SIZE];
	} u;
};

struct xfrm_query {
    uint32_t spi;
    uint32_t daddr;

};

static void netlink_xfrm_message_processor(struct nlm_resp *rsp)
{


	switch (rsp->n.nlmsg_type) {

    case XFRM_MSG_NEWSA:
    case XFRM_MSG_UPDSA:
        printf("xfrm new sa\n");
        struct xfrm_usersa_info* sainfo = (struct xfrm_usersa_info*) NLMSG_DATA(&rsp->n);

        uint32_t spi_be = sainfo->id.spi;
        uint32_t daddr_be = 0;
        memcpy(&daddr_be, &sainfo->id.daddr, sizeof(uint32_t));
        struct in_addr daddr = {
            .s_addr = daddr_be
        };
        printf("spi: %4x\n", ntohl(spi_be));
        printf("daddr: %s\n", inet_ntoa(daddr));
        break;

	case XFRM_MSG_DELSA:
		printf("xfrm del sa\n");
		break;
    case XFRM_MSG_NEWPOLICY:
    case XFRM_MSG_UPDPOLICY:
		printf("xfrm new policy\n");
        struct xfrm_userpolicy_info* polinfo = (struct xfrm_userpolicy_info*) NLMSG_DATA(&rsp->n);
        
        uint32_t saddr_bep = 0;
        memcpy(&saddr_bep, &polinfo->sel.saddr, sizeof(uint32_t));
        uint32_t saddrp = ntohl(saddr_bep);

        struct in_addr saddrp_in = {
            .s_addr = saddr_bep
        };
        printf("saddr: %s\n", inet_ntoa(saddrp_in));

	
	case XFRM_MSG_ACQUIRE:
		//netlink_acquire(&rsp->n, logger);
        printf("xfrm acquire\n");
		break;

	case XFRM_MSG_EXPIRE: /* SA soft and hard limit */
		//xfrm_kernel_sa_expire(&rsp->n, logger);
        printf("xfrm expire\n");
		break;

	case XFRM_MSG_POLEXPIRE:
		//netlink_policy_expire(&rsp->n, logger);
        printf("policy expire\n");
		break;

	default:
		/* ignored */
        printf("something else\n");
		break;
	}
}


static int netlink_get(int fd){
	struct nlm_resp rsp;
	struct sockaddr_nl addr;
	socklen_t alen = sizeof(addr);
	ssize_t r = recvfrom(fd, &rsp, sizeof(rsp), 0, (struct sockaddr *)&addr, &alen);

	if (r < 0) {
		if (errno == EAGAIN)
			return 0;
		if (errno != EINTR) {
			printf("kernel: recvfrom() failed in netlink_get: \n");
		}
		return 1;
	}

	size_t l = (size_t)r; /* must be non -ve */
	if (l < sizeof(rsp.n)) {
		printf("kernel: netlink_get read truncated message: %zu bytes; ignore message\n", l);
		return 1;
	}

	if (addr.nl_pid != 0) {
		/* not for us: ignore */
		printf("ignoring message from process\n");
		return 1;
	}

	if (l != rsp.n.nlmsg_len) {
		printf("kernel: netlink_get: read message with length %zu that doesn't equal nlmsg_len %zu bytes; ignore message\n",l, (size_t) rsp.n.nlmsg_len);
		return 1;
	}

	netlink_xfrm_message_processor(&rsp);
	return 1;
}



static void* init_netlink_xfrm_fd(void* varg){

    netlink_xfrm_fd = socket(AF_NETLINK, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, NETLINK_XFRM);

	if (netlink_xfrm_fd < 0) {
		printf("socket() for bcast in init_netlink()\n");
        return 0;
	}

	struct sockaddr_nl addr;
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_pad = 0; /* make coverity happy */
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE | XFRMGRP_SA| XFRMGRP_POLICY;
	if (bind(netlink_xfrm_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		printf("failed to bind bcast socket in init_netlink() - perhaps kernel was not compiled with CONFIG_XFRM\n");
        return 0;
	}


    do{
        netlink_get(netlink_xfrm_fd);
    }while(keep_alive);

}


static int kernel_xfrm_init(){

	nl_send_fd = socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_XFRM);

	if (nl_send_fd < 0) {
        printf("socket failed\n");
		return 0;
	}

#ifdef SOL_NETLINK
	const int on = 1;
	if (setsockopt(nl_send_fd, SOL_NETLINK, NETLINK_CAP_ACK,
		       (const void *)&on, sizeof(on)) < 0) {
		printf("xfrm: setsockopt(NETLINK_CAP_ACK) failed: \n");
        return 0;
	} else {
		printf("xfrm: setsockopt(NETLINK_CAP_ACK) ok\n");
	}
	if (setsockopt(nl_send_fd, SOL_NETLINK, NETLINK_EXT_ACK,
		       (const void *)&on, sizeof(on)) < 0) {
		printf("xfrm: setsockopt(NETLINK_EXT_ACK) failed: \n");
        return 0;
	} else {
		printf("xfrm: setsockopt(NETLINK_EXT_ACK) ok\n");
	}
#endif

    return 1;

}


static int sendrecv_xfrm_msg(struct nlmsghdr *hdr,
			      unsigned expected_resp_type,
			      struct nlm_resp *rbuf,
			      int *recv_errno)
{
	size_t len = hdr->nlmsg_len;

	ssize_t r;
	static uint32_t seq = 0;	/* STATIC */

	*recv_errno = 0;

	hdr->nlmsg_seq = ++seq;
	do {
		r = write(nl_send_fd, hdr, len);
	} while (r < 0 && errno == EINTR);

	if (r < 0) {
		printf("netlink write() message failed: \n");
		return 0;
	}

	if ((size_t)r != len) {
		printf("netlink write() message truncated:\n");
		return 0;
	}

	struct nlm_resp rsp;
	for (;;) {
		struct sockaddr_nl addr;
		socklen_t alen = sizeof(addr);

		r = recvfrom(nl_send_fd, &rsp, sizeof(rsp), 0,
			(struct sockaddr *)&addr, &alen);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			*recv_errno = errno;
			printf("netlink recvfrom() of response to our message failed: \n");
			return 0;
		}

		size_t l = (size_t) r; /* must be non -ve */
		if (l < sizeof(rsp.n)) {
			printf("netlink read truncated message: %zu bytes; ignore message\n", l);
			continue;
		}

		if (addr.nl_pid != 0) {
			/* not for us: ignore */
			printf("ignoring message from process\n");
			continue;
		}

		if (rsp.n.nlmsg_seq != seq) {
			printf("ignoring out of sequence message\n");
			continue;
		}
		break;
	}

	if (rsp.n.nlmsg_len > (size_t) r) {
		printf("netlink recvfrom() of response to our message was truncated\n");
		return 0;
	}

	/*
	 * Is an error expected? Dump or log it.
	 */
	if (rsp.n.nlmsg_type == NLMSG_ERROR) {
		if (expected_resp_type == NLMSG_ERROR) {
            printf("expected netlink error response: \n");
			/* ignore */
		} else if (rsp.u.e.error == 0) {
			/*
			 * What the heck does a 0 error mean?
			 *
			 * Since the caller doesn't depend on the
			 * result we'll let it pass.  This really
			 * happens for netlink_add_sa().
			 */

			/* ignore */
            printf("error 0\n");
		} 
	}

	if (rsp.n.nlmsg_type != expected_resp_type) {
		if (rbuf == NULL) {
			printf("rbuf NULL: %d\n", rsp.n.nlmsg_type);
	
			return 1;
		}

		printf("rbuff not null: %d\n", rsp.n.nlmsg_type);

		return 0;
	}

	memcpy(rbuf, &rsp, r);
	return 1;
}


static int xfrm_get_kernel_state(struct xfrm_query *sa, uint64_t *bytes,
				  uint64_t *add_time, struct xfrm_algo_aead* crypt)
{
	NL_XFRM_REQ req;

	struct nlm_resp rsp;

	memset(&req, 0, sizeof(NL_XFRM_REQ));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETSA;

    uint32_t _daddrbe = htonl(sa->daddr);

    memcpy(&req.id.daddr, &_daddrbe, sizeof(uint32_t));

	req.id.spi = htonl(sa->spi);
	req.id.family = AF_INET;
	req.id.proto = IPPROTO_ESP;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	int recv_errno;
	if (!sendrecv_xfrm_msg(&req.n, XFRM_MSG_NEWSA, &rsp, &recv_errno)) {
		return 0;
	}
    

	*bytes = rsp.u.info.curlft.bytes;
	*add_time = rsp.u.info.curlft.add_time;

	/* Run through rtattributes looking for XFRMA_LASTUSED */
	struct rtattr *attr = (struct rtattr *) ((char *) NLMSG_DATA(&rsp.n) +
			NLMSG_ALIGN(sizeof(struct xfrm_usersa_info)));
	size_t remaining = rsp.n.nlmsg_len -
				NLMSG_SPACE(sizeof(struct xfrm_usersa_info));
	while (remaining > 0) {
		switch (attr->rta_type) {
        case XFRMA_ALG_AEAD:
            printf("got aead\n");
            size_t alg_key_offset = __builtin_offsetof(struct xfrm_algo_aead, alg_key);
            memcpy(crypt, RTA_DATA(attr), sizeof(struct xfrm_algo_aead));
            memcpy(crypt->alg_key, (char *)RTA_DATA(attr) + alg_key_offset, crypt->alg_key_len / 8);
        case XFRMA_ALG_CRYPT:
            printf("got crypt\n");
		case XFRMA_LASTUSED:
			printf("got last used\n");
            //memcpy(crypt, RTA_DATA(attr), sizeof(uint64_t));
			break;
		default:
            printf("got something else: %d\n", attr->rta_type);
			break;
		}
		attr = RTA_NEXT(attr, remaining); /* updates remaining too */
	}

	return 1;
}


int main(){

    pthread_t tid;

    if(!kernel_xfrm_init()){
        printf("failed to do xfrm init\n");
        return -1;
    }

    pthread_create(&tid, NULL, init_netlink_xfrm_fd, NULL);

    uint32_t spi1 = 0x01000000;
    uint32_t spi2 = 0x02000000;

    uint32_t daddr1 = ntohl(inet_addr("192.168.62.6"));
    uint32_t daddr2 = ntohl(inet_addr("192.168.62.5"));

    struct xfrm_algo_aead crypt1 = {0};
    struct xfrm_algo_aead crypt2 = {0};


    for(;;){

        uint8_t run[8] = {0};
        printf("hit enter to get sa: ");
        fgets(run, 8, stdin);

        struct xfrm_query q1;
        struct xfrm_query q2;
        uint64_t q1len;
        uint64_t q2len;
        uint64_t q1time;
        uint64_t q2time;

        memset(&q1, 0, sizeof(struct xfrm_query));
        memset(&q2, 0, sizeof(struct xfrm_query));

        q1.spi = spi1;
        q1.daddr = daddr1;

        q2.spi = spi2;
        q2.daddr = daddr2;

        if(!xfrm_get_kernel_state(&q1, &q1len, &q1time, &crypt1)){
            printf("q1 failed to get\n");
        } else {
            printf("q1 success\n");
            printf("q1 data len: %lu\n", q1len);
            printf("q1 add time: %lu\n", q1time);
            printf("q1 algo: %s\n", crypt1.alg_name);
            printf("q1 algo key len: %d\n", crypt1.alg_key_len);
            printf("q1 key first 4: %02x%02x%02x%02x\n", crypt1.alg_key[0], crypt1.alg_key[1], crypt1.alg_key[2],crypt1.alg_key[3]);
        
            memset(&crypt1, 0, sizeof(struct xfrm_algo_aead));
        }

        if(!xfrm_get_kernel_state(&q2, &q2len, &q2time, &crypt2)){
            printf("q2 failed to get\n");
        } else {
            printf("q2 success\n");
            printf("q2 success\n");
            printf("q2 data len: %lu\n", q2len);
            printf("q2 add time: %lu\n", q2time);
            printf("q2 algo: %s\n", crypt2.alg_name);
            printf("q2 algo key len: %d\n", crypt2.alg_key_len);
            printf("q2 key first 4: %02x%02x%02x%02x\n", crypt2.alg_key[0], crypt2.alg_key[1], crypt2.alg_key[2], crypt2.alg_key[3]);
            memset(&crypt2,0, sizeof(struct xfrm_algo_aead));
        }

    }

    keep_alive = 1;
    printf("success\n");

    return 0;


}