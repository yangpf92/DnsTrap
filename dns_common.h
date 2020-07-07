
#ifndef __DNS_COMMON_H
#define __DNS_COMMON_H

#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>

#if defined(DBG_DNS_TRAP)
#define DBGP_DNS_TRAP(format, arg...) \
  do {                                \
    printk(format, ##arg);            \
  } while (0)
#else
#define DBGP_DNS_TRAP(format, arg...)
#endif

typedef int (*fn_dnstrap)(struct sk_buff *skb);

void str_to_lower(char *s);

#endif