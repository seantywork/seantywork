#ifndef _GPIO_IRQSK_H_ 
#define _GPIO_IRQSK_H_

#include <linux/kernel.h>
#include <linux/init.h> 
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/gpio.h>

#include <linux/slab.h> 
#include <linux/errno.h>  
#include <linux/types.h> 
#include <linux/interrupt.h> 

#include <linux/in.h>
#include <linux/netdevice.h> 
#include <linux/etherdevice.h>
#include <linux/ip.h>          
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/version.h> 
#include <linux/skbuff.h>

#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <asm/atomic.h>
#include <asm/checksum.h>

#define DRV_NAME	"geth"

#define GETH_TIMEOUT 5

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

#define MAX_PKTLEN 1500
#define MAX_Q_LEN 128

#define SYNC_UDELAY 64



struct geth_packet {
	struct geth_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct geth_priv {
    struct net_device_stats stats;
    int status;
    struct geth_packet *ppool;
    struct geth_packet *rx_queue; 
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


extern struct net_device *geth_devs;
extern struct geth_priv *geth_privs;


extern const struct net_device_ops geth_netdev_ops;

extern const struct header_ops geth_header_ops;

extern int lockup;

extern int timeout;

extern int pool_size;

extern void (*geth_interrupt)(int, void *, struct pt_regs *);



extern int gpio_ctl_o;
extern int gpio_ctl_i;
extern int gpio_data_o;
extern int gpio_data_i;

extern unsigned int gpio_ctl_i_irq;
extern unsigned int gpio_data_i_irq;

extern int comms_mode_o;

extern int comms_mode_i;
extern int ctl_bits_count;
extern int data_bits_count;

extern u8 o_value[MAX_PKTLEN];
extern u8 i_value[MAX_PKTLEN];

extern int i_q_ptr;
extern int i_q_len[MAX_Q_LEN];
extern u8 i_q[MAX_Q_LEN][MAX_PKTLEN];

netdev_tx_t geth_xmit(struct sk_buff *skb, struct net_device *dev);

void geth_hw_tx(char *buf, int len, struct net_device *dev);


int geth_open(struct net_device *dev);

int geth_stop(struct net_device *dev);




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void geth_tx_timeout(struct net_device *dev);

#else 

void geth_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void geth_setup(struct net_device *dev);


void gpio_ctl_on(void);

void gpio_data_on(void);

void gpio_tx(u8* data, int datalen);

irqreturn_t gpio_ctl_irq_handler(int irq, void *dev_id);

irqreturn_t gpio_data_irq_handler(int irq, void *dev_id);

#endif