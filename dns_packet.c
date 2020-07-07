#include "dns_packet.h"
extern unsigned char g_domain_name[80];

static unsigned char dns_answer[] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x04};

static int get_domain_name(unsigned char *dns_body, char *domain_name,
                           int body_len) {
  int offset = 0, token_len = 0;
  char token[64] = {0};
  char domain[128] = {0};
  short type;
  if (!dns_body || !domain_name || body_len <= 0) {
    return -1;
  }
  while (body_len > 0) {
    memset(token, 0, sizeof(token));
    token_len = dns_body[offset];
    if ((token_len > 0) && (token_len <= body_len)) {
      strncpy(token, dns_body + offset + 1, token_len);
      if (!domain[0]) {
        strncpy(domain, token, (sizeof(token) - 1));
      } else {
        strncat(domain, ".", (sizeof(domain) - strlen(domain) - 1));
        strncat(domain, token, (sizeof(domain) - strlen(domain) - 1));
      }
    } else {
      if (token_len > body_len)
        printk("%s[%d], token_len is %d, body_len is %d\n", __FUNCTION__,
               __LINE__, token_len, body_len);
      break;
    }
    token_len += 1;
    body_len -= token_len;
    offset += token_len;
  }
  strncpy(domain_name, domain, (sizeof(domain) - 1));
  return 0;
}

static bool is_valid_dns_query_header(dnsheader_t *dns_header) {
  if (dns_header == NULL) {
    return false;
  }
  DBGP_DNS_TRAP("[%s]qdcount:%d\n", __FUNCTION__, dns_header->qdcount);
  if (dns_header->qdcount < 1) {
    return false;
  }
  if (((dns_header->u & 0x8000) >> 15) !=
      0) /*QR: query should be 0,answer be 1*/
  {
    DBGP_DNS_TRAP("[%s]QR!=0!\n", __FUNCTION__);
    return false;
  }
  if (((dns_header->u & 0x7100) >> 11) !=
      0) /*opcode: 0:standard,1:reverse,2:server status*/
  {
    DBGP_DNS_TRAP("[%s]opcode!=0!\n", __FUNCTION__);
    return false;
  }
  if (((dns_header->u & 0x70) >> 4) != 0) /*Z: reserved, should be 0*/
  {
    DBGP_DNS_TRAP("[%s]Z!=0!\n", __FUNCTION__);
    return false;
  }
  return true;
}

static bool is_domain_name_equal(char *domain_name1, char *domain_name2) {
  char temp1[128];
  char temp2[128];
  if (!domain_name1 || !domain_name2) {
    return false;
  }
  str_to_lower(domain_name1);
  str_to_lower(domain_name2);
  if (!strncmp(domain_name1, "www.", 4)) {
    strcpy(temp1, domain_name1 + 4);
  } else {
    strcpy(temp1, domain_name1);
  }
  if (!strncmp(domain_name2, "www.", 4)) {
    strcpy(temp2, domain_name2 + 4);
  } else {
    strcpy(temp2, domain_name2);
  }
  if (strcmp(temp1, temp2))
    return false;
  else
    return true;
}

// TODO: 该函数是核心函数，设计到数据包的修改
int br_dns_packet_recap(struct sk_buff *skb) {
  struct iphdr *iph;
  struct udphdr *udph;
  struct net_device *br0_dev;
  struct in_device *br0_in_dev;
  dnsheader_t *dns_pkt;
  unsigned char mac[ETH_ALEN];
  unsigned int ip;
  unsigned short port;
  unsigned char *ptr = NULL;
  int extend_len;
  extend_len = EXTEND_LEN_V4;
  /*
  关于net_device和in_device详见https://blog.csdn.net/sinat_20184565/article/details/79898433
  我们这里的需要返回br0当前的ip地址，所以需要获取用户给br0配置的ip地址，所以需要该函数
  TODO: 用完该结构我们必须要调用put来进行释放
  */
  br0_dev = dev_get_by_name(&init_net, "br0");
  br0_in_dev = in_dev_get(br0_dev);

  if (!br0_dev || !br0_in_dev) {
    if (br0_in_dev) in_dev_put(br0_in_dev);
    if (br0_dev) dev_put(br0_dev);
    return -1;
  }
  /*
    in_ifaddr表示地址结构，其成员包含了地址，掩码，范围等信息，多个地址连接成链表，主地址在前，从地址在后；
    struct in_ifaddr    *ifa_list;    /* IP ifaddr chain
    如果br0接口配置的有ip地址，子网掩码等，所有的信息都存放在这里(我们可以从该结构中拿到当前的br0的ip地址)
*/

  if (!br0_in_dev->ifa_list) {
    in_dev_put(br0_in_dev);
    dev_put(br0_dev);
    return -1;
  }
  iph = ip_hdr(skb);
  udph = (void *)iph + iph->ihl * 4;

  dns_pkt = (void *)udph + sizeof(struct udphdr);

  // ptr为尾部指针，指向了dns请求报文的尾部
  ptr = (void *)udph + ntohs(udph->len);
  /*
  将数据段向后扩大extend_len的长度(这里是16个字节，ip地址为4个字节，固定长度12个字节)
  该条语句的操作可以参考wireshark抓包。
  TODO:下面这句话是该整个修改数据包函数的核心思想
  TODO:dns的回复报文需要在请求报文(queries字段)的后面添加应答字段(answers),具体可以查看
        上面的博客连接和通过抓包分析
        answers字段中的前12个字段是固定的，12个字段后面接的是ip地址
        所以是16个字节
  */
  skb_put(skb, extend_len);

  // TODO:下面的操作其实都是在操作五元组，内核中数据包的流向都是靠五元组(源)
  /*
          源IP地址、目的IP地址、协议号、源端口、目的端口(协议号已经是有的了)
  */

  //交换mac地址
  /*
    在网络通信的是否，数据包中的地址变化过程如下：(不在同一局域网)
    源mac地址为当前设备的mac地址，目的mac是下一条设备的mac地址
    目的ip不变，源ip地址是为当前设备的ip地址。

    在这里的理解为：
    当pc访问www.baidu.com的时候，首先会向网关发送dns请求。(此时的源mac地址为pc的mac，目的mac地址为网关。源ip地址为pc的ip地址，目的ip地址为网关的ip地址)
    当我们在网关拦截到数据包的时候，需要交换数据报文中的mac地址和ip地址。
  */
  memcpy(mac, eth_hdr(skb)->h_dest, ETH_ALEN);
  memcpy(eth_hdr(skb)->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
  memcpy(eth_hdr(skb)->h_source, mac, ETH_ALEN);

  //交换ip地址
  ip = iph->saddr;
  iph->saddr = iph->daddr;
  iph->daddr = ip;

  //重新计算ip头部信心中的tot_len,tot_len代表ip数据包的长度
  iph->tot_len = htons(ntohs(iph->tot_len) + extend_len);
  DBGP_DNS_TRAP("[%s]iph->tot_len:%d\n", __FUNCTION__, iph->tot_len);

  /*  交换udp端口 */
  port = udph->source;
  udph->source = udph->dest;
  udph->dest = port;

  //计算udp头部的长度
  udph->len = htons(ntohs(udph->len) + extend_len);

  //下面是根据wireshark抓包得到的
  dns_pkt->u = htons(0x8180);
  dns_pkt->qdcount = htons(1);
  dns_pkt->ancount = htons(1);
  dns_pkt->nscount = htons(0);
  dns_pkt->arcount = htons(0);
  DBGP_DNS_TRAP("[%s]udph->len:%d\n", __FUNCTION__, ntohs(udph->len));
  DBGP_DNS_TRAP("[%s]dns_pkt->u:%x\n", __FUNCTION__, ntohs(dns_pkt->u));
  DBGP_DNS_TRAP("[%s]dns_pkt->qdcount:%x\n", __FUNCTION__,
                ntohs(dns_pkt->qdcount));
  DBGP_DNS_TRAP("[%s]dns_pkt->ancount:%x\n", __FUNCTION__,
                ntohs(dns_pkt->ancount));
  DBGP_DNS_TRAP("[%s]dns_pkt->nscount:%x\n", __FUNCTION__,
                ntohs(dns_pkt->nscount));
  DBGP_DNS_TRAP("[%s]dns_pkt->arcount:%x\n", __FUNCTION__,
                ntohs(dns_pkt->arcount));
  //填充12位固定的数据
  memcpy(ptr, dns_answer, 12);
  //将br0的ip地址填充到skb中
  memcpy(ptr + 12, (unsigned char *)&br0_in_dev->ifa_list->ifa_address, 4);

  /* ip checksum */
  // TODO: CHECKSUM_NONE表示发送侧已经计算了校验和，协议栈将不会再计算校验和
  skb->ip_summed = CHECKSUM_NONE;

  //计算ip头部校验和,在计算之前应该先赋值为0
  iph->check = 0;
  iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

  /* udp checksum */
  udph->check = 0;
  udph->check =
      csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP,
                        csum_partial((char *)udph, ntohs(udph->len), 0));
  if (br0_in_dev) {
    in_dev_put(br0_in_dev);
  }
  if (br0_dev) {
    dev_put(br0_dev);
  }

  return 1;
}

/*
    该函数只会判断ipv4的报文，ipv6的报文这里不会涉及
*/
int br_dns_trap_enter(struct sk_buff *skb) {
  struct iphdr *iph;
  struct udphdr *udph;

  iph = (struct iphdr *)skb_network_header(skb);

  //判断是否为ipv4的报文
  if (iph->version != 4) {
    return -1;
  }
  //获取udp头部
  udph = (void *)iph + iph->ihl * 4;
  // DNS报文是属于udp数据包，同时端口号为53
  if (iph->protocol != IPPROTO_UDP || ntohs(udph->dest) != 53) {
    return -1;
  }
  //获取DNS报文中的domain_name的长度
  /*
    说明：udp数据包头部信息中的len字段是udp头部信息和数据信息的总长度
    domain_name_len的长度和我们在应用层看到的domain_name的长度不一样，比如应用层我们看到的www.baidu.com他的长度为12个字节。
    但是在数据包中一般为14个字节，因为他会指明域名的长度(具体看wireshark抓包截图)
    ntohs(udph->len) - sizeof(struct udphdr) -
    sizeof(dnsheader_t)代表的是dns请求报文中的Queries字段的长度。该字段也是放在报文的最后面(我们请求的域名就包含在该字段中)
    那么这里为什么还要减去4呢，因Queries中有4个字节是固定的，分别为Type和Class字段，他们一共占据4个字节。减去4之后剩下的，才是我们真正的domain_name_len的长度
  */
  int domain_name_len =
      ntohs(udph->len) - sizeof(struct udphdr) - sizeof(dnsheader_t) - 4;
  if (domain_name_len <= 1) {
    return -1;
  }
  // 获取dns头部信息
  dnsheader_t *dns_hdr = (dnsheader_t *)((void *)udph + sizeof(struct udphdr));

  //判断dns头部是否有效
  if (is_valid_dns_query_header(dns_hdr) != true) {
    return -1;
  }
  //获取dns中的数据包
  unsigned char *body =
      (void *)udph + sizeof(struct udphdr) + sizeof(dnsheader_t);

  //获取dns数据包中的domain_len(这里是按照wireshark中来解析的)
  unsigned char domain_name[128] = {0};
  if (get_domain_name(body, domain_name, domain_name_len) != 0) {
    return -1;
  }

  //判断报文中获取到的domain_name和应用层传入的domain_name是否相等
  if (is_domain_name_equal(domain_name, g_domain_name) == false) {
    return -1;
  }
  //上面的匹配都满足了，证明该数据包我们需要处理，这里处理的核心思想就是改变原有数据包，然后发送。
  br_dns_packet_recap(skb);
}