#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/etherdevice.h>

struct net_device *virtualNIC;

int virtualNIC_init(struct net_device *dev) {
  printk("virtualNIC device initialized\n");
  return 0;
};


int virtualNIC_open(struct net_device *dev) {
printk("virtualNIC_open called\n");
return 0;
}

int virtualNIC_release(struct net_device *dev) {
printk("virtualNIC_release called\n");
netif_stop_queue(dev);
return 0;
}

int virtualNIC_xmit(struct sk_buff *skb, struct net_device *dev) {
 printk("dummy xmit function called...\n");
 dev_kfree_skb(skb);
 return 0;
}

const struct net_device_ops my_netdev_ops = {
     .ndo_init = virtualNIC_init,
     .ndo_open = virtualNIC_open,
     .ndo_stop = virtualNIC_release,
     .ndo_start_xmit = virtualNIC_xmit,
 };


static void virtual_setup(struct net_device *dev){
  dev->netdev_ops = &my_netdev_ops;
 }

 int virtualNIC_init_module(void) {
 int result;
 virtualNIC = alloc_netdev(0, "virtnC%d", NET_NAME_UNKNOWN, virtual_setup);
 if((result = register_netdev(virtualNIC))) {
  printk("virtualNIC: Error %d initalizing card ...", result);
  return result;
 }
 return 0;
}

void virtualNIC_cleanup (void)
{
  printk ("<0> Cleaning Up the Module\n");
  unregister_netdev (virtualNIC);
 }

module_init(virtualNIC_init_module);
module_exit(virtualNIC_cleanup);
MODULE_LICENSE("GPL");