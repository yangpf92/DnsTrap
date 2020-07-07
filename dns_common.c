#include "dns_common.h"

void str_to_lower(char *s) {
  if (s != NULL) {
    while (*s != '\0') {
      *s = __tolower(*s);
      ++s;
    }
  }
}