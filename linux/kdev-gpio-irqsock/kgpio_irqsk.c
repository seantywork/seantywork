#include "kgpio_irqsk.h"


struct net_device *geth_devs;
struct geth_priv *geth_privs;


int lockup = 0;
int timeout = GETH_TIMEOUT;
int pool_size = 8;


void (*geth_interrupt)(int, void *, struct pt_regs *);

int gpio_ctl_o;
int gpio_ctl_i;
int gpio_data_o;
int gpio_data_i;

module_param(gpio_ctl_o, int, 0664);
module_param(gpio_ctl_i, int, 0664);
module_param(gpio_data_o, int, 0664);
module_param(gpio_data_i, int, 0664);

unsigned int gpio_ctl_i_irq;
unsigned int gpio_data_i_irq;

int comms_mode_o = 0;

int comms_mode_i = 0;
int ctl_bits_count = 0;
int data_bits_count = 0;

u8 o_value[MAX_PKTLEN] = {0};
u8 i_value[MAX_PKTLEN] = {0};


int i_q_ptr = -1;
int i_q_len[MAX_Q_LEN];
u8 i_q[MAX_Q_LEN][MAX_PKTLEN];

spinlock_t q_lock;


void geth_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs){

    printk(KERN_INFO "napi interrupt\n");

	struct geth_priv *priv;
	struct net_device *dev = (struct net_device *)dev_id;

	if (!dev){
        printk(KERN_INFO "invalid dev\n");
		return;
    }

	priv = netdev_priv(dev);

	printk(KERN_INFO "napi receive\n");

	//spin_lock(&q_lock);

	i_q_ptr += 1;
	i_q_len[i_q_ptr] = data_bits_count / 8;
	memcpy(i_q[i_q_ptr], i_value, i_q_len[i_q_ptr]);

	//spin_unlock(&q_lock);

	napi_schedule(&priv->napi);

    printk(KERN_INFO "napi interrupt end\n");

	return;
}


int geth_poll(struct napi_struct *napi, int budget){


	int npackets = 0;
	struct sk_buff *skb;
	struct geth_priv *priv = container_of(napi, struct geth_priv, napi);
	struct net_device *dev = priv->dev;
	struct geth_packet pkt;
	
	//spin_lock(&q_lock);

	pkt.dev = dev;
	pkt.datalen = i_q_len[i_q_ptr];
	memcpy(pkt.data, i_q[i_q_ptr], pkt.datalen);

	//spin_unlock(&q_lock);

    printk(KERN_INFO "polling\n");

	while (npackets < budget && (i_q_ptr + 1)) {

		i_q_ptr -= 1;

		skb = dev_alloc_skb(NET_IP_ALIGN + pkt.datalen);
		if (! skb) {
			if (printk_ratelimit()){
                printk(KERN_INFO "geth: packet dropped\n");
            }
			priv->stats.rx_dropped++;
			npackets++;
			continue;
		}
		skb_reserve(skb, NET_IP_ALIGN);  
		memcpy(skb_put(skb, pkt.datalen), pkt.data, pkt.datalen);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		netif_receive_skb(skb);

		npackets++;
		priv->stats.rx_packets++;
		priv->stats.rx_bytes += pkt.datalen;
	}

    printk(KERN_INFO "polling done\n");

	if (npackets < budget) {
        printk(KERN_INFO "npackets smaller than budget\n");
		unsigned long flags;
		spin_lock_irqsave(&priv->lock, flags);
		if (napi_complete_done(napi, npackets)){
			printk(KERN_INFO "napi complete\n");
        }
		spin_unlock_irqrestore(&priv->lock, flags);
	}


    printk(KERN_INFO "polling end\n");

	return npackets;

}



netdev_tx_t geth_xmit(struct sk_buff *skb, struct net_device *dev){

    printk("entered xmit\n");

	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct geth_priv *priv = netdev_priv(dev);

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

	geth_hw_tx(data, len, dev);

    printk("exiting xmit\n");

	return 0;


}


void geth_hw_tx(char *buf, int len, struct net_device *dev){


    printk(KERN_INFO "entered hw tx\n");

	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;
	struct tcphdr *th;

	struct geth_priv *priv;
	u16 sport;
	u16 dport;


	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("geth: packet too short (%i octets)\n",
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
		ntohl(ih->saddr), sport);

	printk("dst: %08x:%05i\n",
		ntohl(ih->daddr), dport);


	
	gpio_tx((u8*)buf, len);

	priv = netdev_priv(dev);

	priv->stats.tx_packets++;
	priv->stats.tx_bytes += len;
	if(priv->skb) {
		dev_kfree_skb(priv->skb);
		priv->skb = 0;
	}
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {

		netif_stop_queue(dev);
		printk(KERN_INFO "simulate lockup at %ld, txp %ld\n", jiffies, (unsigned long) priv->stats.tx_packets);

	} 

}




int geth_open(struct net_device *dev){

	char macaddr[ETH_ALEN] = {0};

	int val = gpio_data_i - gpio_ctl_i;

	printk(KERN_INFO "geth mac val: %d\n", val);

	sprintf(macaddr, "GETH0%d", val);

	memcpy((void*)dev->dev_addr, macaddr, ETH_ALEN);

	struct geth_priv *priv = netdev_priv(dev);
	napi_enable(&priv->napi);

	netif_start_queue(dev);

    printk(KERN_INFO "started geth\n");

	return 0;
}

int geth_stop(struct net_device *dev){

	netif_stop_queue(dev);

	struct geth_priv *priv = netdev_priv(dev);
	napi_disable(&priv->napi);

	return 0;

    printk(KERN_INFO "stopped geth\n");
}




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void geth_tx_timeout(struct net_device *dev)

#else 

void geth_tx_timeout(struct net_device *dev, unsigned int txqueue)

#endif 

{
	struct geth_priv *priv = netdev_priv(dev);
    struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	printk(KERN_INFO "transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - txq->trans_start);

	geth_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;

	spin_lock(&priv->lock);
	spin_unlock(&priv->lock);

	netif_wake_queue(dev);
	return;
}



const struct net_device_ops geth_netdev_ops = {
	.ndo_open            = geth_open,
	.ndo_stop            = geth_stop,
	.ndo_start_xmit      = geth_xmit,
	.ndo_tx_timeout      = geth_tx_timeout,
};




void geth_setup(struct net_device *dev){

	ether_setup(dev); 
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &geth_netdev_ops;
	dev->features        |= NETIF_F_HW_CSUM;

	geth_privs = netdev_priv(dev);

	memset(geth_privs, 0, sizeof(struct geth_priv));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
	netif_napi_add(dev, &geth_privs->napi, geth_poll,2);
#else 
	netif_napi_add_weight(dev, &geth_privs->napi, geth_poll,2);
#endif

    spin_lock_init(&q_lock);
	spin_lock_init(&geth_privs->lock);
	geth_privs->dev = dev;

	printk(KERN_INFO "geth: setup success\n");
}




void gpio_ctl_on(void){

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

	udelay(SYNC_UDELAY);

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);
}

void gpio_data_on(void){

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

	udelay(SYNC_UDELAY);

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);

}

void gpio_tx(u8* data, int datalen){

	for(int i = 0; i < 3; i++){

		gpio_ctl_on();
	}

	gpio_data_on();

	for(int i = 0; i < datalen; i++) {

		for(int j = 0; j < 8; j++){

			if(CHECK_BIT(data[i], j)){

				if(!comms_mode_o){

					gpio_ctl_on();

					comms_mode_o = 1;
				}

				gpio_data_on();

			} else {

				if(comms_mode_o){
					
					gpio_ctl_on();

					comms_mode_o = 0;
				}

				gpio_data_on();

			}

		}

	}

	for(int i = 0; i < 3; i++){

		gpio_ctl_on();
	}
	
	gpio_data_on();

	comms_mode_o = 0;

}


irqreturn_t gpio_ctl_irq_handler(int irq, void *dev_id) {
	ctl_bits_count += 1;
	return IRQ_HANDLED;
}

irqreturn_t gpio_data_irq_handler(int irq, void *dev_id) {

	int pktidx = 0;
	int bitidx = 0;

	if(ctl_bits_count == 3){
		ctl_bits_count = 0;
		if(data_bits_count == 0){
			return IRQ_HANDLED;
		} else {
			if(gpio_ctl_i != 0 && gpio_ctl_o != 0){

				geth_interrupt(0, geth_devs, NULL);
			}else {
				printk("value: %02x%02x%02x%02x...%02x%02x%02x%02x\n", 
					i_value[0],
					i_value[1],
					i_value[2],
					i_value[3],
					i_value[MAX_PKTLEN-4],
					i_value[MAX_PKTLEN-3],
					i_value[MAX_PKTLEN-2],
					i_value[MAX_PKTLEN-1]
				);
			}
			memset(i_value, 0, MAX_PKTLEN);
			data_bits_count = 0;
			comms_mode_i = 0;
			return IRQ_HANDLED;
		}
	}

	if(ctl_bits_count == 1){
		ctl_bits_count = 0;
		if(comms_mode_i){
			comms_mode_i = 0;
		} else {
			comms_mode_i = 1;
		}
	}

	pktidx = data_bits_count / 8;
	bitidx = data_bits_count % 8;

	if(comms_mode_i){

		i_value[pktidx] = i_value[pktidx] | (1 << bitidx);

	} else {

		i_value[pktidx] = i_value[pktidx] | (0 << bitidx);

	}

	data_bits_count += 1;

	return IRQ_HANDLED;
}

static DECLARE_WAIT_QUEUE_HEAD(this_wq);

static int condition;

static struct work_struct job;

static void job_handler(struct work_struct* work){

    printk(KERN_INFO "waitqueue handler: %s\n", __FUNCTION__);

	printk(KERN_INFO "waitqueue handler waiting...\n");

	msleep(100);

	printk(KERN_INFO "sending ctl start preamble\n");

	gpio_tx(o_value, MAX_PKTLEN);

    condition = 1;

    wake_up_interruptible(&this_wq);

}


static int __init ksock_gpio_init(void) {

	int err;

	if(gpio_ctl_o == 0 && gpio_ctl_i == 0){

		printk("gpio irqsk: at least one ctl should be set\n");
		return -1;

	}

	if(gpio_ctl_o != 0){

		if(gpio_data_o == 0){
			printk("gpio irqsk: gpio_ctl_o should also set gpio_data_o\n");
			return -1;
		}

		if(gpio_request(gpio_ctl_o, "gpio-ctl-o")) {
			printk("gpio irqsk: can't allocate gpio_ctl_o: %d\n", gpio_ctl_o);
			return -1;
		}		

		if(gpio_direction_output(gpio_ctl_o, IRQF_TRIGGER_NONE)) {
			printk("gpio irqsk: can't set gpio_ctl_o to output\n");
			gpio_free(gpio_ctl_o);
			return -1;
		}

		if(gpio_request(gpio_data_o, "gpio-data-o")) {
			printk("gpio irqsk: can't allocate gpio_data_o: %d\n", gpio_data_o);
			gpio_free(gpio_ctl_o);
			return -1;
		}		

		if(gpio_direction_output(gpio_data_o, IRQF_TRIGGER_NONE)) {
			printk("gpio irqsk: can't set gpio_data_o to output\n");
			gpio_free(gpio_ctl_o);
			gpio_free(gpio_data_o);
			return -1;
		}
	}

	if(gpio_ctl_i != 0){

		if(gpio_data_i == 0){
			printk("gpio irqsk: gpio_ctl_i should also set gpio_data_i\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			return -1;
		}

		if(gpio_request(gpio_ctl_i, "gpio-ctl-i")) {
			printk("gpio irqsk: can't allocate gpio_ctl_i: %d\n", gpio_ctl_i);
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			return -1;
		}


		if(gpio_direction_input(gpio_ctl_i)) {
			printk("gpio irqsk: can't set gpio_ctl_i to input\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			return -1;
		}

		if(gpio_request(gpio_data_i, "gpio-data-i")) {
			printk("gpio irqsk: can't allocate gpio_data_i: %d\n", gpio_data_i);
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			return -1;
		}


		if(gpio_direction_input(gpio_data_i)) {
			printk("gpio irqsk: can't set gpio_data_i to input\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			return -1;
		}


		gpio_ctl_i_irq = gpio_to_irq(gpio_ctl_i);

		if(request_irq(gpio_ctl_i_irq, gpio_ctl_irq_handler, IRQF_TRIGGER_RISING, "gpio_ctl_i_irq", NULL) != 0) {
			printk("gpio irqsk: can't request interrupt\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			return -1;
		}

		gpio_data_i_irq = gpio_to_irq(gpio_data_i);

		if(request_irq(gpio_data_i_irq, gpio_data_irq_handler, IRQF_TRIGGER_RISING, "gpio_data_i_irq", NULL) != 0) {
			printk("gpio irqsk: can't request interrupt\n");
			if(gpio_ctl_o != 0){
				gpio_free(gpio_ctl_o);
				gpio_free(gpio_data_o);
			}
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			free_irq(gpio_ctl_i_irq, NULL);
			return -1;
		}

		printk("gpio irqsk: gpio_ctl_i to IRQ %d\n", gpio_ctl_i_irq);

		printk("gpio irqsk: gpio_data_i to IRQ %d\n", gpio_data_i_irq);
	}

	printk("gpio irqsk: module is initialized into the kernel\n");

	printk("gpio irqsk: ctl_o: %d ctl_i: %d\n", gpio_ctl_o, gpio_ctl_i);
	printk("gpio irqsk: data_o: %d data_i: %d\n", gpio_data_o, gpio_data_i);
	

	if(gpio_ctl_o != 0 && gpio_ctl_i == 0){

		printk("gpio irqsk: test mode\n");

		get_random_bytes(o_value, MAX_PKTLEN);

		printk("value: %02x%02x%02x%02x...%02x%02x%02x%02x\n", 
			o_value[0],
			o_value[1],
			o_value[2],
			o_value[3],
			o_value[MAX_PKTLEN-4],
			o_value[MAX_PKTLEN-3],
			o_value[MAX_PKTLEN-2],
			o_value[MAX_PKTLEN-1]
		);
		INIT_WORK(&job, job_handler);

		for(int i = 0; i < 10; i++){
			schedule_work(&job);

			wait_event_interruptible(this_wq, condition != 0);

			condition = 0;
		}

		printk(KERN_INFO "job done\n");

	}
	if(gpio_ctl_o != 0 && gpio_ctl_i != 0){

		printk("gpio irqsk: prod mode\n");

		geth_interrupt = geth_napi_interrupt;

		geth_devs = alloc_netdev(sizeof(struct geth_priv), "geth%d", NET_NAME_UNKNOWN, geth_setup);
		if (!geth_devs){
			printk("gpio irqsk: can't alloc netdev\n");
			gpio_free(gpio_ctl_o);
			gpio_free(gpio_data_o);
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			free_irq(gpio_ctl_i_irq, NULL);
			free_irq(gpio_data_i_irq, NULL);
			return -ENOMEM;
		}

		err = register_netdevice(geth_devs);
		if (err < 0) {
			printk("gpio irqsk: can't register netdev\n");
			gpio_free(gpio_ctl_o);
			gpio_free(gpio_data_o);
			gpio_free(gpio_ctl_i);
			gpio_free(gpio_data_i);
			free_irq(gpio_ctl_i_irq, NULL);
			free_irq(gpio_data_i_irq, NULL);
			free_netdev(geth_devs);
			return -1;
		}

	}


	return 0;

}

static void __exit ksock_gpio_exit(void) {


	if(gpio_ctl_o != 0){

		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
	}
	if(gpio_ctl_i != 0){
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		free_irq(gpio_ctl_i_irq, NULL);
		free_irq(gpio_data_i_irq, NULL);
	}

	if(gpio_ctl_i != 0 && gpio_ctl_o != 0){

		unregister_netdev(geth_devs);
		free_netdev(geth_devs);
	}

	printk("gpio irqsk: module is removed from the kernel\n");
}

module_init(ksock_gpio_init);
module_exit(ksock_gpio_exit);

MODULE_LICENSE("GPL");