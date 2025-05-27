#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>

static int __init ksock_gpio_init(void) {

	return 0;
}

static void __exit ksock_gpio_exit(void) {

}

module_init(ksock_gpio_init);
module_exit(ksock_gpio_exit);

MODULE_LICENSE("GPL");