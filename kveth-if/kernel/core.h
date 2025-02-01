#ifndef _DUMMETH_X_H_ 
#define _DUMMETH_X_H_ 



#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> 

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>
#include <linux/version.h> 

#include <linux/in6.h>
#include <asm/checksum.h>

#define DRV_NAME	"dummeth"
#define DRV_COUNT   2


#define DUMMETH_RX_INTR 0x0001
#define DUMMETH_TX_INTR 0x0002

/* Default timeout period */
#define DUMMETH_TIMEOUT 5   /* In jiffies */



struct dummeth_packet {
	struct dummeth_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct dummeth_priv {
    struct net_device_stats stats;
    int status;
    struct dummeth_packet *ppool;
    struct dummeth_packet *rx_queue; /* List of incoming packets */
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


extern struct net_device *dummeth_devs[DRV_COUNT];
extern struct dummeth_priv *dummeth_privs[DRV_COUNT];
extern int setup_ptr;

extern const struct net_device_ops dummeth_netdev_ops;

extern const struct header_ops dummeth_header_ops;

extern int lockup;

extern int timeout;

extern int use_napi;

extern int pool_size;

extern void (*dummeth_interrupt)(int, void *, struct pt_regs *);

/* util functions */

void dummeth_setup_pool(struct net_device *dev);

void dummeth_teardown_pool(struct net_device *dev);

struct dummeth_packet *dummeth_get_tx_buffer(struct net_device *dev);

void dummeth_release_buffer(struct dummeth_packet *pkt);

void dummeth_enqueue_buf(struct net_device *dev, struct dummeth_packet *pkt);

struct dummeth_packet *dummeth_dequeue_buf(struct net_device *dev);


/* rx, interrupt functions */

void dummeth_rx_ints(struct net_device *dev, int enable);

void dummeth_rx(struct net_device *dev, struct dummeth_packet *pkt);

int dummeth_poll(struct napi_struct *napi, int budget);

void dummeth_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs);

void dummeth_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

/* device specific hw tx functions */

void dummeth_hw_tx(char *buf, int len, struct net_device *dev);


/* header and etc */

int dummeth_rebuild_header(struct sk_buff *skb);

int dummeth_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len);

int dummeth_change_mtu(struct net_device *dev, int new_mtu);


/* netdev */

int dummeth_open(struct net_device *dev);

int dummeth_stop(struct net_device *dev);

int dummeth_set_config(struct net_device *dev, struct ifmap *map);

netdev_tx_t dummeth_xmit(struct sk_buff *skb, struct net_device *dev);

int dummeth_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);

//int dummeth_get_stats(struct net_device *dev);

struct net_device_stats* dummeth_get_stats(struct net_device *dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void dummeth_tx_timeout(struct net_device *dev);

#else 

void dummeth_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void dummeth_setup(struct net_device *dev);

#endif