#ifndef __DNS_PROC_H
#define __DNS_PROC_H

#include "dns_common.h"

#define PROC_ROOT "dns_filter"
#define PROC_DOMAIN_NAME "domain_name"
#define PROC_ENABLE "enable"

void create_dnstrap_proc();
void destroy_dnstrap_proc();

#endif