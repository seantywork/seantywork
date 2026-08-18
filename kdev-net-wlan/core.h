#ifndef _WLANIDT_CORE_H_
#define _WLANIDT_CORE_H_


#include <linux/module.h>

#include <net/cfg80211.h> 
#include <linux/skbuff.h>

#include <linux/workqueue.h> 
#include <linux/semaphore.h>

#define WIPHY_NAME "kwlanidiot"
#define NDEV_NAME "wlanidt%d"
#define SSID_DUMMY "APIDIOT"
#define SSID_DUMMY_SIZE (sizeof("APIDIOT") - 1)

int __init virtual_wifi_init(void);


void __exit virtual_wifi_exit(void);

struct wlanidt_context {
  struct wiphy *wiphy;
  struct net_device *ndev;
  struct semaphore sem;
  struct work_struct ws_connect;
  char connecting_ssid[sizeof(SSID_DUMMY)];
  struct work_struct ws_disconnect;
  u16 disconnect_reason_code;
  struct work_struct ws_scan;
  struct cfg80211_scan_request *scan_request;
};


struct wlanidt_wiphy_priv_context {
    struct wlanidt_context *wictx;
};

struct wlanidt_ndev_priv_context {
    struct wlanidt_context *wictx;
    struct wireless_dev wdev;
};

struct wlanidt_wiphy_priv_context *wiphy_get_wi_context(struct wiphy *wiphy);

struct wlanidt_ndev_priv_context *ndev_get_wi_context(struct net_device *ndev);

void inform_dummy_bss(struct wlanidt_context *wictx);

void wlanidt_scan_routine(struct work_struct *w);

void wlanidt_connect_routine(struct work_struct *w);

void wlanidt_disconnect_routine(struct work_struct *w);

int wi_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request);

int wi_connect(struct wiphy *wiphy, struct net_device *dev,
                struct cfg80211_connect_params *sme);

int wi_disconnect(struct wiphy *wiphy, struct net_device *dev,
                   u16 reason_code);

netdev_tx_t wi_ndo_start_xmit(struct sk_buff *skb,
                               struct net_device *dev);

struct wlanidt_context *wlanidt_create_context(void);


void wlanidt_free(struct wlanidt_context *ctx);

int __init virtual_wifi_init(void);

void __exit virtual_wifi_exit(void);

extern struct wlanidt_context *g_ctx;



#endif