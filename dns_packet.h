#ifndef __DNS_PACKET_H
#define __DNS_PACKET_H

#include "dns_common.h"

#define EXTEND_LEN_V4 16

typedef struct _header {
  unsigned short int id;  // id 位
  unsigned short u;       //标志位

  short int qdcount;  //问题数
  short int ancount;  //资源记录数
  short int nscount;  //授权资源记录数
  short int arcount;  //问题资源记录数
} dnsheader_t;

int br_dns_trap_enter(struct sk_buff *skb);

#endif