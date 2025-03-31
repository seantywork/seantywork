
#include "deth.h"



struct net_device *deth_devs[DRV_COUNT];
struct deth_priv *deth_privs[DRV_COUNT];
int setup_ptr= 0;


int lockup = 0;
int timeout = DETH_TIMEOUT;
int pool_size = 8;


void (*deth_interrupt)(int, void *, struct pt_regs *);


void deth_setup_pool(struct net_device *dev){

	struct deth_priv *priv = netdev_priv(dev);
	int i;
	struct deth_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct deth_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_INFO "out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}


}


void deth_teardown_pool(struct net_device *dev){

	struct deth_priv *priv = netdev_priv(dev);
	struct deth_packet *pkt;

	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}    


struct deth_packet *deth_get_tx_buffer(struct net_device *dev){

	struct deth_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct deth_packet *pkt;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	if(!pkt) {
		// PDEBUG("Out of Pool\n");
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

void deth_release_buffer(struct deth_packet *pkt){

	unsigned long flags;
	struct deth_priv *priv = netdev_priv(pkt->dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL){

        netif_wake_queue(pkt->dev);
    }


}

void deth_enqueue_buf(struct net_device *dev, struct deth_packet *pkt){

	unsigned long flags;
	struct deth_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);


}



struct deth_packet *deth_dequeue_buf(struct net_device *dev){

	struct deth_priv *priv = netdev_priv(dev);
	struct deth_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL){
        priv->rx_queue = pkt->next;
    }
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;

}

void deth_rx_ints(struct net_device *dev, int enable){

	struct deth_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}



int deth_poll(struct napi_struct *napi, int budget){


	int npackets = 0;
	struct sk_buff *skb;
	struct deth_priv *priv = container_of(napi, struct deth_priv, napi);
	struct net_device *dev = priv->dev;
	struct deth_packet *pkt;

    printk(KERN_INFO "polling\n");

	while (npackets < budget && priv->rx_queue) {
		pkt = deth_dequeue_buf(dev);
		skb = dev_alloc_skb(pkt->datalen + 2);
		if (! skb) {
			if (printk_ratelimit()){
                printk(KERN_INFO "deth: packet dropped\n");
            }
			priv->stats.rx_dropped++;
			npackets++;
			deth_release_buffer(pkt);
			continue;
		}
		skb_reserve(skb, 2);  
		memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		netif_receive_skb(skb);

		npackets++;
		priv->stats.rx_packets++;
		priv->stats.rx_bytes += pkt->datalen;
		deth_release_buffer(pkt);
	}

    printk(KERN_INFO "polling done\n");

	if (npackets < budget) {
        printk(KERN_INFO "npackets smaller than budget\n");
		unsigned long flags;
		spin_lock_irqsave(&priv->lock, flags);
		if (napi_complete_done(napi, npackets)){
			printk(KERN_INFO "napi complete\n");
            //deth_rx_ints(dev, 1);
        }
		spin_unlock_irqrestore(&priv->lock, flags);
	}

    printk(KERN_INFO "polling end\n");

	return npackets;

}


void deth_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs){

    printk(KERN_INFO "napi interrupt\n");

	int statusword;
	struct deth_priv *priv;


	struct net_device *dev = (struct net_device *)dev_id;

	if (!dev){
        printk(KERN_INFO "invalid dev\n");
		return;
    }

	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & DETH_RX_INTR) {
        printk(KERN_INFO "napi receive\n");
		//deth_rx_ints(dev, 0);  
		napi_schedule(&priv->napi);
	}
	if (statusword & DETH_TX_INTR) {
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

void deth_hw_tx(char *buf, int len, struct net_device *dev){


    printk(KERN_INFO "entered hw tx\n");
	/*
	 * This function deals with hw details. This interface loops
	 * back the packet to the other deth interface (if any).
	 * In other words, this function implements the deth behaviour,
	 * while all other procedures are rather device-independent
	 */
	struct iphdr *ih;
	struct net_device *dest;
	struct deth_priv *priv;
	u32 *saddr, *daddr;
	struct deth_packet *tx_buffer;

	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("deth: packet too short (%i octets)\n",
				len);
		return;
	}


    // enable this conditional to look at the data

    int i;
    printk(KERN_INFO "len is %i\n",len);
    //for (i=14 ; i<len; i++)
    //    printk(" %02x",buf[i]&0xff);
    //printk("\n");



	/*
	 * Ethhdr is 14 bytes, but the kernel arranges for iphdr
	 * to be aligned (i.e., ethhdr is unaligned)
	 */
	/*
	ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	((u8 *)saddr)[2] ^= 1; 
	((u8 *)daddr)[2] ^= 1;

	ih->check = 0;         
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);


	if (dev == deth_devs[0])
		printk(KERN_INFO "%08x:%05i --> %08x:%05i\n",
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));
	else
		printk(KERN_INFO "%08x:%05i <-- %08x:%05i\n",
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

	*/


	dest = deth_devs[dev == deth_devs[0] ? 1 : 0];
	priv = netdev_priv(dest);
	
	struct deth_priv *spriv = netdev_priv(dev);

	printk(KERN_INFO "src: rx_int_enabled: %d\n", spriv->rx_int_enabled);
	printk(KERN_INFO "dst: rx_int_enabled: %d\n", priv->rx_int_enabled);
	
	tx_buffer = deth_get_tx_buffer(dev);

	if(!tx_buffer) {
		printk(KERN_INFO "out of tx buffer, len is %i\n",len);
		return;
	}

	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	deth_enqueue_buf(dest, tx_buffer);
	if (priv->rx_int_enabled) {

		priv->status |= DETH_RX_INTR;
		deth_interrupt(0, dest, NULL);
	}

	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= DETH_TX_INTR;
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {
        	/* Simulate a dropped transmit interrupt */
		netif_stop_queue(dev);
		printk(KERN_INFO "simulate lockup at %ld, txp %ld\n", jiffies, (unsigned long) priv->stats.tx_packets);
	}
	else{

        deth_interrupt(0, dev, NULL);
    }



}



int deth_rebuild_header(struct sk_buff *skb){

	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;

	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return 0;

}




int deth_header(struct sk_buff *skb, struct net_device *dev,
	unsigned short type, const void *daddr, const void *saddr,
	unsigned len){

	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;  
	return (dev->hard_header_len);

}



/*
int deth_change_mtu(struct net_device *dev, int new_mtu){

	unsigned long flags;
	struct deth_priv *priv = netdev_priv(dev);
	spinlock_t *lock = &priv->lock;

	if ((new_mtu < 68) || (new_mtu > 1500)){

        return -EINVAL;
    }

	spin_lock_irqsave(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	return 0; 

}
*/

int deth_open(struct net_device *dev){

	if (dev == deth_devs[1]){

        memcpy(dev->dev_addr, "DETH01", ETH_ALEN);


    } else {

		memcpy(dev->dev_addr, "DETH00", ETH_ALEN);
	}

	struct deth_priv *priv = netdev_priv(dev);
	napi_enable(&priv->napi);

	netif_start_queue(dev);

    printk(KERN_INFO "started deth\n");

	return 0;
}

int deth_stop(struct net_device *dev){

	netif_stop_queue(dev);

	struct deth_priv *priv = netdev_priv(dev);
	napi_disable(&priv->napi);

	return 0;

    printk(KERN_INFO "stopped deth\n");
}

/*
int deth_set_config(struct net_device *dev, struct ifmap *map){

	if (dev->flags & IFF_UP){
        return -EBUSY;
    }

	if (map->base_addr != dev->base_addr) {
		printk(KERN_INFO "deth: can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	if (map->irq != dev->irq) {

		dev->irq = map->irq;

	}

	return 0;
}
*/

netdev_tx_t deth_xmit(struct sk_buff *skb, struct net_device *dev){

    printk("entered xmit\n");

	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct deth_priv *priv = netdev_priv(dev);

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

	deth_hw_tx(data, len, dev);


    printk("exiting xmit\n");

	return 0;



}

/*
int deth_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd){


    printk(KERN_INFO "deth ioctl\n");
	return 0;
}
*/

/*
struct net_device_stats* deth_get_stats(struct net_device *dev){

	struct deth_priv *priv = netdev_priv(dev);
	return &priv->stats;

}
*/


#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void deth_tx_timeout(struct net_device *dev)

#else 

void deth_tx_timeout(struct net_device *dev, unsigned int txqueue)

#endif 

{
	struct deth_priv *priv = netdev_priv(dev);
    struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	printk(KERN_INFO "transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - txq->trans_start);

	priv->status |= DETH_TX_INTR;
	deth_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;

	spin_lock(&priv->lock);
	deth_teardown_pool(dev);
	deth_setup_pool(dev);
	spin_unlock(&priv->lock);

	netif_wake_queue(dev);
	return;
}


const struct header_ops deth_header_ops = {
    .create = deth_header
};



const struct net_device_ops deth_netdev_ops = {
	.ndo_open            = deth_open,
	.ndo_stop            = deth_stop,
	.ndo_start_xmit      = deth_xmit,
//	.ndo_do_ioctl        = deth_do_ioctl,
//	.ndo_set_config      = deth_set_config,
//	.ndo_get_stats       = deth_get_stats,
//	.ndo_change_mtu      = deth_change_mtu,
	.ndo_tx_timeout      = deth_tx_timeout,
};




void deth_setup(struct net_device *dev){

	ether_setup(dev); 
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &deth_netdev_ops;
//	dev->header_ops = &deth_header_ops;
	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_HW_CSUM;

	deth_privs[setup_ptr] = netdev_priv(dev);

	memset(deth_privs[setup_ptr], 0, sizeof(struct deth_priv));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
	netif_napi_add(dev, &(deth_privs[setup_ptr])->napi, deth_poll,2);
#else 
	netif_napi_add_weight(dev, &(deth_privs[setup_ptr])->napi, deth_poll,2);
#endif

	spin_lock_init(&(deth_privs[setup_ptr])->lock);
	deth_privs[setup_ptr]->dev = dev;

	deth_rx_ints(dev, 1);	
	deth_setup_pool(dev);

	setup_ptr += 1;

	printk(KERN_INFO "deth: setup success: %d\n", setup_ptr);
}


static int __init deth_init_module(void){

	int err;

	deth_interrupt = deth_napi_interrupt;

	deth_devs[0] = alloc_netdev(sizeof(struct deth_priv), "deth%d", NET_NAME_UNKNOWN, deth_setup);
	if (!deth_devs[0]){
        return -ENOMEM;
    }

	deth_devs[1] = alloc_netdev(sizeof(struct deth_priv), "deth%d", NET_NAME_UNKNOWN, deth_setup);

	if (!deth_devs[1]){
        return -ENOMEM;
    }

	err = register_netdevice(deth_devs[0]);
	if (err < 0) {
        goto err1;
    }

    err = register_netdevice(deth_devs[1]);

    if(err < 0) {

        goto err2;
    }


	return 0;

err1:

	free_netdev(deth_devs[0]);
	return err;

err2:
	free_netdev(deth_devs[0]);
    free_netdev(deth_devs[1]);
	return err; 

}



static void __exit deth_cleanup_module(void)
{
	int i;

	for (i = 0; i < DRV_COUNT; i++) {
		if (deth_devs[i]) {
			unregister_netdev(deth_devs[i]);
			deth_teardown_pool(deth_devs[i]);
			free_netdev(deth_devs[i]);
		}
	}
	return;
}




module_init(deth_init_module);
module_exit(deth_cleanup_module);
MODULE_LICENSE("GPL");