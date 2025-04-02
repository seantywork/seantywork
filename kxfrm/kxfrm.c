
#include "kxfrm.h"



struct net_device *kxfrm_devs[DRV_COUNT];
struct kxfrm_priv *kxfrm_privs[DRV_COUNT];
int setup_ptr= 0;


int lockup = 0;
int timeout = KXFRM_TIMEOUT;
int pool_size = 8;


void (*kxfrm_interrupt)(int, void *, struct pt_regs *);


void kxfrm_setup_pool(struct net_device *dev){

	struct kxfrm_priv *priv = netdev_priv(dev);
	int i;
	struct kxfrm_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct kxfrm_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_INFO "out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}


}


void kxfrm_teardown_pool(struct net_device *dev){

	struct kxfrm_priv *priv = netdev_priv(dev);
	struct kxfrm_packet *pkt;

	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
	}
}    


struct kxfrm_packet *kxfrm_tx_cons_buffer(struct net_device *dev){

	struct kxfrm_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct kxfrm_packet *pkt;

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

void kxfrm_tx_release_buffer(struct kxfrm_packet *pkt){

	unsigned long flags;
	struct kxfrm_priv *priv = netdev_priv(pkt->dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL){

        netif_wake_queue(pkt->dev);
    }


}

void kxfrm_rx_prod_buf(struct net_device *dev, struct kxfrm_packet *pkt){

	unsigned long flags;
	struct kxfrm_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);


}



struct kxfrm_packet *kxfrm_rx_cons_buf(struct net_device *dev){

	struct kxfrm_priv *priv = netdev_priv(dev);
	struct kxfrm_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL){
        priv->rx_queue = pkt->next;
    }
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;

}

void kxfrm_rx_ints(struct net_device *dev, int enable){

	struct kxfrm_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}




void kxfrm_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs){

    printk(KERN_INFO "napi interrupt\n");

	int statusword;
	struct kxfrm_priv *priv;


	struct net_device *dev = (struct net_device *)dev_id;

	if (!dev){
        printk(KERN_INFO "invalid dev\n");
		return;
    }

	priv = netdev_priv(dev);
	spin_lock(&priv->lock);


	statusword = priv->status;
	priv->status = 0;
	if (statusword & KXFRM_RX_INTR) {
        printk(KERN_INFO "napi receive\n");
		napi_schedule(&priv->napi);
	}
	if (statusword & KXFRM_TX_INTR) {
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


int kxfrm_poll(struct napi_struct *napi, int budget){


	int npackets = 0;
	struct sk_buff *skb;
	struct kxfrm_priv *priv = container_of(napi, struct kxfrm_priv, napi);
	struct net_device *dev = priv->dev;
	struct kxfrm_packet *pkt;

    printk(KERN_INFO "polling\n");

	while (npackets < budget && priv->rx_queue) {
		pkt = kxfrm_rx_cons_buf(dev);
		skb = dev_alloc_skb(NET_IP_ALIGN + pkt->datalen);
		if (! skb) {
			if (printk_ratelimit()){
                printk(KERN_INFO "kxfrm: packet dropped\n");
            }
			priv->stats.rx_dropped++;
			npackets++;
			kxfrm_tx_release_buffer(pkt);
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
		kxfrm_tx_release_buffer(pkt);
	}

    printk(KERN_INFO "polling done\n");

	if (npackets < budget) {
        printk(KERN_INFO "npackets smaller than budget\n");
		unsigned long flags;
		spin_lock_irqsave(&priv->lock, flags);
		if (napi_complete_done(napi, npackets)){
			printk(KERN_INFO "napi complete\n");
            //kxfrm_rx_ints(dev, 1);
        }
		spin_unlock_irqrestore(&priv->lock, flags);
	}

    printk(KERN_INFO "polling end\n");

	return npackets;

}



netdev_tx_t kxfrm_xmit(struct sk_buff *skb, struct net_device *dev){

    printk("entered xmit\n");

	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct kxfrm_priv *priv = netdev_priv(dev);

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

	kxfrm_hw_tx(data, len, dev);

    printk("exiting xmit\n");

	return 0;


}


void kxfrm_hw_tx(char *buf, int len, struct net_device *dev){


    printk(KERN_INFO "entered hw tx\n");

	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;
	struct tcphdr *th;

	struct net_device *dest;
	struct kxfrm_priv *priv;
	u16 sport;
	u16 dport;
	struct kxfrm_packet *tx_buffer;

	__be32 haddr;

	struct net* net = NULL;
    struct rtable *rt = NULL;
    struct neighbour *n = NULL;

	dest = kxfrm_devs[dev == kxfrm_devs[0] ? 1 : 0];

	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("kxfrm: packet too short (%i octets)\n",
				len);
		return;
	}

	eh = (struct ethhdr*)buf;

	ih = (struct iphdr*)(buf + sizeof(struct ethhdr));

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

	tx_buffer = kxfrm_tx_cons_buffer(dev);

	if(!tx_buffer) {
		printk(KERN_INFO "out of tx buffer, len is %i\n",len);
		return;
	}

	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	kxfrm_rx_prod_buf(dest, tx_buffer);
	if (priv->rx_int_enabled) {

		priv->status |= KXFRM_RX_INTR;
		kxfrm_interrupt(0, dest, NULL);
	}

	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= KXFRM_TX_INTR;
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {

		netif_stop_queue(dev);
		printk(KERN_INFO "simulate lockup at %ld, txp %ld\n", jiffies, (unsigned long) priv->stats.tx_packets);

	} else{

        kxfrm_interrupt(0, dev, NULL);
    }


}




int kxfrm_open(struct net_device *dev){

	if (dev == kxfrm_devs[1]){

        memcpy((void*)dev->dev_addr, "KXFRM1", ETH_ALEN);


    } else {

		memcpy((void*)dev->dev_addr, "KXFRM0", ETH_ALEN);
	}

	struct kxfrm_priv *priv = netdev_priv(dev);
	napi_enable(&priv->napi);

	netif_start_queue(dev);

    printk(KERN_INFO "started kxfrm\n");

	return 0;
}

int kxfrm_stop(struct net_device *dev){

	netif_stop_queue(dev);

	struct kxfrm_priv *priv = netdev_priv(dev);
	napi_disable(&priv->napi);

	return 0;

    printk(KERN_INFO "stopped kxfrm\n");
}




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void kxfrm_tx_timeout(struct net_device *dev)

#else 

void kxfrm_tx_timeout(struct net_device *dev, unsigned int txqueue)

#endif 

{
	struct kxfrm_priv *priv = netdev_priv(dev);
    struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	printk(KERN_INFO "transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - txq->trans_start);

	priv->status |= KXFRM_TX_INTR;
	kxfrm_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;

	spin_lock(&priv->lock);
	kxfrm_teardown_pool(dev);
	kxfrm_setup_pool(dev);
	spin_unlock(&priv->lock);

	netif_wake_queue(dev);
	return;
}



const struct net_device_ops kxfrm_netdev_ops = {
	.ndo_open            = kxfrm_open,
	.ndo_stop            = kxfrm_stop,
	.ndo_start_xmit      = kxfrm_xmit,
	.ndo_tx_timeout      = kxfrm_tx_timeout,
};




void kxfrm_setup(struct net_device *dev){

	ether_setup(dev); 
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &kxfrm_netdev_ops;
//	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_HW_CSUM;

	kxfrm_privs[setup_ptr] = netdev_priv(dev);

	memset(kxfrm_privs[setup_ptr], 0, sizeof(struct kxfrm_priv));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
	netif_napi_add(dev, &(kxfrm_privs[setup_ptr])->napi, kxfrm_poll,2);
#else 
	netif_napi_add_weight(dev, &(kxfrm_privs[setup_ptr])->napi, kxfrm_poll,2);
#endif

	spin_lock_init(&(kxfrm_privs[setup_ptr])->lock);
	kxfrm_privs[setup_ptr]->dev = dev;

	kxfrm_rx_ints(dev, 1);	
	kxfrm_setup_pool(dev);

	setup_ptr += 1;

	printk(KERN_INFO "kxfrm: setup success: %d\n", setup_ptr);
}


static int __init kxfrm_init_module(void){

	int err;

	kxfrm_interrupt = kxfrm_napi_interrupt;

	kxfrm_devs[0] = alloc_netdev(sizeof(struct kxfrm_priv), "kxfrm%d", NET_NAME_UNKNOWN, kxfrm_setup);
	if (!kxfrm_devs[0]){
        return -ENOMEM;
    }

	kxfrm_devs[1] = alloc_netdev(sizeof(struct kxfrm_priv), "kxfrm%d", NET_NAME_UNKNOWN, kxfrm_setup);

	if (!kxfrm_devs[1]){
        return -ENOMEM;
    }

	err = register_netdevice(kxfrm_devs[0]);
	if (err < 0) {
        goto err1;
    }

    err = register_netdevice(kxfrm_devs[1]);

    if(err < 0) {

        goto err2;
    }


	return 0;

err1:

	free_netdev(kxfrm_devs[0]);
	return err;

err2:
	free_netdev(kxfrm_devs[0]);
    free_netdev(kxfrm_devs[1]);
	return err; 

}



static void __exit kxfrm_cleanup_module(void)
{
	int i;

	for (i = 0; i < DRV_COUNT; i++) {
		if (kxfrm_devs[i]) {
			unregister_netdev(kxfrm_devs[i]);
			kxfrm_teardown_pool(kxfrm_devs[i]);
			free_netdev(kxfrm_devs[i]);
		}
	}
	return;
}




module_init(kxfrm_init_module);
module_exit(kxfrm_cleanup_module);
MODULE_LICENSE("GPL");