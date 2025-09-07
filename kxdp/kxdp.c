
#include "kxdp.h"



struct net_device *kxdp_devs[DRV_COUNT];
struct kxdp_priv *kxdp_privs[DRV_COUNT];
int setup_ptr= 0;


int lockup = 0;
int timeout = KXDP_TIMEOUT;
int pool_size = 8;


void (*kxdp_interrupt)(int, void *, struct pt_regs *);


void kxdp_setup_pool(struct net_device *dev){

	struct kxdp_priv *priv = netdev_priv(dev);
	int i;
	struct kxdp_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct kxdp_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_INFO "out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}


}


void kxdp_teardown_pool(struct net_device *dev){

	struct kxdp_priv *priv = netdev_priv(dev);
	struct kxdp_packet *pkt;

	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
	}
}    


struct kxdp_packet *kxdp_tx_cons_buffer(struct net_device *dev){

	struct kxdp_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct kxdp_packet *pkt;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	if(!pkt) {
        printk (KERN_INFO "out of pool\n");
		return pkt;
	}
	priv->ppool = pkt->next;
	if (priv->ppool == NULL) {
		printk (KERN_INFO "pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;


}

void kxdp_tx_release_buffer(struct kxdp_packet *pkt){

	unsigned long flags;
	struct kxdp_priv *priv = netdev_priv(pkt->dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL){

        netif_wake_queue(pkt->dev);
    }


}

void kxdp_rx_prod_buf(struct net_device *dev, struct kxdp_packet *pkt){

	unsigned long flags;
	struct kxdp_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);


}



struct kxdp_packet *kxdp_rx_cons_buf(struct net_device *dev){

	struct kxdp_priv *priv = netdev_priv(dev);
	struct kxdp_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL){
        priv->rx_queue = pkt->next;
    }
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;

}

void kxdp_rx_ints(struct net_device *dev, int enable){

	struct kxdp_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}




void kxdp_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs){

    printk(KERN_INFO "napi interrupt\n");

	int statusword;
	struct kxdp_priv *priv;


	struct net_device *dev = (struct net_device *)dev_id;

	if (!dev){
        printk(KERN_INFO "invalid dev\n");
		return;
    }

	priv = netdev_priv(dev);
	spin_lock(&priv->lock);


	statusword = priv->status;
	priv->status = 0;
	if (statusword & KXDP_RX_INTR) {
        printk(KERN_INFO "napi receive\n");
		napi_schedule(&priv->napi);
	}
	if (statusword & KXDP_TX_INTR) {
        printk(KERN_INFO "napi transmit\n");
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		if(priv->skb) {
			dev_kfree_skb(priv->skb);
			priv->skb = 0;
		}
	}

    printk(KERN_INFO "napi interrupt end\n");

	spin_unlock(&priv->lock);
	return;
}


int kxdp_poll(struct napi_struct *napi, int budget){


	int npackets = 0;
	struct sk_buff *skb;
	struct kxdp_priv *priv = container_of(napi, struct kxdp_priv, napi);
	struct net_device *dev = priv->dev;
	struct kxdp_packet *pkt;

    printk(KERN_INFO "polling\n");

	while (npackets < budget && priv->rx_queue) {
		pkt = kxdp_rx_cons_buf(dev);
		skb = dev_alloc_skb(NET_IP_ALIGN + pkt->datalen);
		if (! skb) {
			if (printk_ratelimit()){
                printk(KERN_INFO "kxdp: packet dropped\n");
            }
			priv->stats.rx_dropped++;
			npackets++;
			kxdp_tx_release_buffer(pkt);
			continue;
		}
		skb_reserve(skb, NET_IP_ALIGN);  
		memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		netif_receive_skb(skb);

		npackets++;
		priv->stats.rx_packets++;
		priv->stats.rx_bytes += pkt->datalen;
		kxdp_tx_release_buffer(pkt);
	}

    printk(KERN_INFO "polling done\n");

	if (npackets < budget) {
        printk(KERN_INFO "npackets smaller than budget\n");
		unsigned long flags;
		spin_lock_irqsave(&priv->lock, flags);
		if (napi_complete_done(napi, npackets)){
			printk(KERN_INFO "napi complete\n");
            //kxdp_rx_ints(dev, 1);
        }
		spin_unlock_irqrestore(&priv->lock, flags);
	}

    printk(KERN_INFO "polling end\n");

	return npackets;

}



netdev_tx_t kxdp_xmit(struct sk_buff *skb, struct net_device *dev){

    printk("entered xmit\n");

	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct kxdp_priv *priv = netdev_priv(dev);

	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	netif_trans_update(dev);

	priv->skb = skb;

	kxdp_hw_tx(data, len, dev);

    printk("exiting xmit\n");

	return 0;


}


void kxdp_hw_tx(char *buf, int len, struct net_device *dev){


    printk(KERN_INFO "entered hw tx\n");

	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;
	struct tcphdr *th;

	struct net_device *dest;
	struct kxdp_priv *priv;
	u16 sport;
	u16 dport;
	struct kxdp_packet *tx_buffer;

	__be32 haddr;

	struct net* net = NULL;
    struct rtable *rt = NULL;
    struct neighbour *n = NULL;

	dest = kxdp_devs[dev == kxdp_devs[0] ? 1 : 0];

	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("kxdp: packet too short (%i octets)\n",
				len);
		return;
	}

	eh = (struct ethhdr*)buf;

	ih = (struct iphdr*)(buf + sizeof(struct ethhdr));

	/*
	net = dev_net(dev);
	
	if(net == NULL){

		printk("kxdp: failed to get dev net\n");

		return;
	}

    rt = ip_route_output(net, ih->daddr,ih->saddr, 0 ,dev->ifindex);

	if(IS_ERR(rt)){

		printk("kxdp: failed to get rt\n");

		return;

	}
	*/

	n = __ipv4_neigh_lookup(dev,ih->daddr);

	if(n == NULL){
		n = neigh_create(&arp_tbl, &ih->daddr, dev);
	}
	if(IS_ERR(n)){

		printk("kxdp: failed to lookup\n");

		return;
	}        

	printk(KERN_INFO "[kxdp] got neigh mac [%pM] ",n->ha);

	printk("eth src: %02X:%02X:%02X:%02X:%02X:%02X\n", 
		eh->h_source[0],  
		eh->h_source[1],  
		eh->h_source[2],  
		eh->h_source[3],  
		eh->h_source[4],  
		eh->h_source[5]);
	printk("eth dst: %02X:%02X:%02X:%02X:%02X:%02X\n", 
		eh->h_dest[0], 
		eh->h_dest[1], 
		eh->h_dest[2], 
		eh->h_dest[3], 
		eh->h_dest[4], 
		eh->h_dest[5]);

	neigh_release(n);

	if(ih->protocol == IPPROTO_UDP){

		uh = (struct udphdr*)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));

		sport = ntohs(uh->source);
		dport = ntohs(uh->dest);

	} else if (ih->protocol == IPPROTO_TCP){

		th = (struct tcphdr*)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));

		sport = ntohs(th->source);
		dport = ntohs(th->dest);

	}

	printk("src: %08x:%05i\n",
		ntohl(ih->daddr), sport);

	printk("dst: %08x:%05i\n",
		ntohl(ih->daddr), dport);


	priv = netdev_priv(dest);

	tx_buffer = kxdp_tx_cons_buffer(dev);

	if(!tx_buffer) {
		printk(KERN_INFO "out of tx buffer, len is %i\n",len);
		return;
	}

	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	kxdp_rx_prod_buf(dest, tx_buffer);
	if (priv->rx_int_enabled) {

		priv->status |= KXDP_RX_INTR;
		kxdp_interrupt(0, dest, NULL);
	}

	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= KXDP_TX_INTR;
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {

		netif_stop_queue(dev);
		printk(KERN_INFO "simulate lockup at %ld, txp %ld\n", jiffies, (unsigned long) priv->stats.tx_packets);

	} else{

        kxdp_interrupt(0, dev, NULL);
    }


}




int kxdp_open(struct net_device *dev){

	if (dev == kxdp_devs[1]){

        memcpy((void*)dev->dev_addr, "KNEI01", ETH_ALEN);


    } else {

		memcpy((void*)dev->dev_addr, "KNEI00", ETH_ALEN);
	}

	struct kxdp_priv *priv = netdev_priv(dev);
	napi_enable(&priv->napi);

	netif_start_queue(dev);

    printk(KERN_INFO "started kxdp\n");

	return 0;
}

int kxdp_stop(struct net_device *dev){

	netif_stop_queue(dev);

	struct kxdp_priv *priv = netdev_priv(dev);
	napi_disable(&priv->napi);

	return 0;

    printk(KERN_INFO "stopped kxdp\n");
}




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void kxdp_tx_timeout(struct net_device *dev)

#else 

void kxdp_tx_timeout(struct net_device *dev, unsigned int txqueue)

#endif 

{
	struct kxdp_priv *priv = netdev_priv(dev);
    struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	printk(KERN_INFO "transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - txq->trans_start);

	priv->status |= KXDP_TX_INTR;
	kxdp_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;

	spin_lock(&priv->lock);
	kxdp_teardown_pool(dev);
	kxdp_setup_pool(dev);
	spin_unlock(&priv->lock);

	netif_wake_queue(dev);
	return;
}



const struct net_device_ops kxdp_netdev_ops = {
	.ndo_open            = kxdp_open,
	.ndo_stop            = kxdp_stop,
	.ndo_start_xmit      = kxdp_xmit,
	.ndo_tx_timeout      = kxdp_tx_timeout,
};




void kxdp_setup(struct net_device *dev){

	ether_setup(dev); 
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &kxdp_netdev_ops;
//	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_HW_CSUM;

	kxdp_privs[setup_ptr] = netdev_priv(dev);

	memset(kxdp_privs[setup_ptr], 0, sizeof(struct kxdp_priv));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
	netif_napi_add(dev, &(kxdp_privs[setup_ptr])->napi, kxdp_poll,2);
#else 
	netif_napi_add_weight(dev, &(kxdp_privs[setup_ptr])->napi, kxdp_poll,2);
#endif

	spin_lock_init(&(kxdp_privs[setup_ptr])->lock);
	kxdp_privs[setup_ptr]->dev = dev;

	kxdp_rx_ints(dev, 1);	
	kxdp_setup_pool(dev);

	setup_ptr += 1;

	printk(KERN_INFO "kxdp: setup success: %d\n", setup_ptr);
}


static int __init kxdp_init_module(void){

	int err;

	kxdp_interrupt = kxdp_napi_interrupt;

	kxdp_devs[0] = alloc_netdev(sizeof(struct kxdp_priv), "kxdp%d", NET_NAME_UNKNOWN, kxdp_setup);
	if (!kxdp_devs[0]){
        return -ENOMEM;
    }

	kxdp_devs[1] = alloc_netdev(sizeof(struct kxdp_priv), "kxdp%d", NET_NAME_UNKNOWN, kxdp_setup);

	if (!kxdp_devs[1]){
        return -ENOMEM;
    }

	err = register_netdevice(kxdp_devs[0]);
	if (err < 0) {
        goto err1;
    }

    err = register_netdevice(kxdp_devs[1]);

    if(err < 0) {

        goto err2;
    }


	return 0;

err1:

	free_netdev(kxdp_devs[0]);
	return err;

err2:
	free_netdev(kxdp_devs[0]);
    free_netdev(kxdp_devs[1]);
	return err; 

}



static void __exit kxdp_cleanup_module(void)
{
	int i;

	for (i = 0; i < DRV_COUNT; i++) {
		if (kxdp_devs[i]) {
			unregister_netdev(kxdp_devs[i]);
			kxdp_teardown_pool(kxdp_devs[i]);
			free_netdev(kxdp_devs[i]);
		}
	}
	return;
}




module_init(kxdp_init_module);
module_exit(kxdp_cleanup_module);
MODULE_LICENSE("GPL");