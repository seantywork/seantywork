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

#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <asm/atomic.h>
#include <asm/checksum.h>


#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

#define MAX_PKTLEN 1500


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


void gpio_ctl_on(void);

void gpio_data_on(void);

void gpio_tx(u8* data, int datalen);

irqreturn_t gpio_ctl_irq_handler(int irq, void *dev_id);

irqreturn_t gpio_data_irq_handler(int irq, void *dev_id);

#endif