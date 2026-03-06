#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]


static struct nf_hook_ops *nf_blockicmp_ops = NULL;
static struct nf_hook_ops *nf_blockport_ops = NULL;


static unsigned int nf_blockport(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb) {
		return NF_ACCEPT;
	} else {

        struct iphdr *iph;
        struct tcphdr *tcph;

        iph = ip_hdr(skb);

	    if (iph->protocol == IPPROTO_TCP) {

            tcph = tcp_hdr(skb);

            if(ntohs(tcph->dest) == 9999) {

                printk(KERN_INFO "knetfilter: drop port 9999 \n");

                return NF_DROP;
            }
	    }

        return NF_ACCEPT;

        /*
        by ip addr
		char *str = (char *)kmalloc(16, GFP_KERNEL);
		u32 sip;
		struct sk_buff *sb = NULL;
		struct iphdr *iph;

		sb = skb;
		iph = ip_hdr(sb);
		sip = ntohl(iph->saddr);
		
		sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));
		if(!strcmp(str, ip_addr_rule)) {
			return NF_DROP;
		} else {
			return NF_ACCEPT;
		}

        */
	}
}


static unsigned int nf_blockicmp(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	if(!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if(ntohs(udph->dest) == 53) {
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	else if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "knetfilter: drop icmp \n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static int __init nf_knetfilter_init(void) {
	nf_blockicmp_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockicmp_ops != NULL) {

		nf_blockicmp_ops->hook = (nf_hookfn*)nf_blockicmp;
		nf_blockicmp_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockicmp_ops->pf = NFPROTO_IPV4;
		nf_blockicmp_ops->priority = NF_IP_PRI_FIRST;
		
		nf_register_net_hook(&init_net, nf_blockicmp_ops);

        printk(KERN_INFO "init knetfilter: block icmp\n");
	}
	nf_blockport_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockport_ops != NULL) {
		nf_blockport_ops->hook = (nf_hookfn*)nf_blockport;
		nf_blockport_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockport_ops->pf = NFPROTO_IPV4;
		nf_blockport_ops->priority = NF_IP_PRI_FIRST + 1;

		nf_register_net_hook(&init_net, nf_blockport_ops);

        printk(KERN_INFO "init knetfilter: block port\n");
	}
	return 0;
}

static void __exit nf_knetfilter_exit(void) {
	if(nf_blockicmp_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_blockicmp_ops);
		kfree(nf_blockicmp_ops);

        printk(KERN_INFO "exit knetfilter: block icmp\n");
	}
	if (nf_blockport_ops  != NULL) {
		nf_unregister_net_hook(&init_net, nf_blockport_ops);
		kfree(nf_blockport_ops);

        printk(KERN_INFO "exit knetfilter: block port\n");
	}
}

module_init(nf_knetfilter_init);
module_exit(nf_knetfilter_exit);

MODULE_LICENSE("GPL");