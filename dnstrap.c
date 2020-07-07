#include "dns_packet.h"
#include "dns_proc.h"

extern bool g_dns_filter_enable;
extern fn_dnstrap g_fn_dnstrap;

static int __init dnstrap_init(void) {
  create_dnstrap_proc();
  g_fn_dnstrap = br_dns_trap_enter;
  return 0;
}

static void __exit dnstrap_eixt(void) {
  destroy_dnstrap_proc();
  g_fn_dnstrap = NULL;
}

MODULE_LICENSE("GPL");

module_init(dnstrap_init);

module_exit(dnstrap_eixt);