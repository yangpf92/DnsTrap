#include "dns_proc.h"

#include "dns_packet.h"

bool dns_trap_enabled = false;
unsigned char g_domain_name[80] = {0};

extern fn_dnstrap g_fn_dnstrap;

static struct proc_dir_entry *dnstrap_proc_root = NULL;

static int dnstrap_domain_read(struct seq_file *s, void *v) {
  seq_printf(s, "%s\n", g_domain_name);
  return 0;
}

static int dnstrap_domain_proc_open(struct inode *inode, struct file *file) {
  return (single_open(file, dnstrap_domain_read, NULL));
}

static int dnstrap_domain_write(struct file *file, const char *buffer,
                                unsigned long count, void *data) {
  if (count < 2) return -EFAULT;

  if (buffer && !copy_from_user(g_domain_name, buffer, 80)) {
    g_domain_name[count - 1] = 0;
    str_to_lower(g_domain_name);
    return count;
  }

  return -EFAULT;
}

int dnstrap_domain_proc_write(struct file *file, const char __user *userbuf,
                              size_t count, loff_t *off) {
  return dnstrap_domain_write(file, userbuf, count, off);
}

struct file_operations dnstrap_domain_proc_fops = {
    .open = dnstrap_domain_proc_open,
    .write = dnstrap_domain_proc_write,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int dnstrap_en_write(struct file *file, const char *buffer,
                            unsigned long count, void *data) {
  char tmpbuf[80];

  if (count < 2) return -EFAULT;

  if (buffer && !copy_from_user(tmpbuf, buffer, count)) {
    tmpbuf[count] = '\0';
    if (tmpbuf[0] == '0') {
      dns_trap_enabled = true;
      g_fn_dnstrap = br_dns_trap_enter;
    } else if (tmpbuf[0] == '1') {
      dns_trap_enabled = false;
      g_fn_dnstrap = NULL;
    }

    return count;
  }
  return -EFAULT;
}

static int dnstrap_en_read(struct seq_file *s, void *v) {
  if (dns_trap_enabled == true) {
    seq_printf(s, "0\n");
  } else {
    seq_printf(s, "1\n");
  }

  return 0;
}

static int dnstrap_en_proc_open(struct inode *inode, struct file *file) {
  return (single_open(file, dnstrap_en_read, NULL));
}
static int dnstrap_en_proc_write(struct file *file, const char __user *userbuf,
                                 size_t count, loff_t *off) {
  return dnstrap_en_write(file, userbuf, count, off);
}

struct file_operations dnstrap_en_proc_fops = {
    .open = dnstrap_en_proc_open,
    .write = dnstrap_en_proc_write,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

void create_dnstrap_proc() {
  dnstrap_proc_root = proc_mkdir(PROC_ROOT, NULL);
  if (dnstrap_proc_root) {
    proc_create_data(PROC_DOMAIN_NAME, 0644, dnstrap_proc_root,
                     &dnstrap_domain_proc_fops, NULL);
    proc_create_data(PROC_ENABLE, 0644, dnstrap_proc_root,
                     &dnstrap_domain_proc_fops, NULL);
  }
}

void destroy_dnstrap_proc() {
  if (dnstrap_proc_root) {
    remove_proc_entry(PROC_DOMAIN_NAME, dnstrap_proc_root);
    remove_proc_entry(PROC_ENABLE, dnstrap_proc_root);
    proc_remove(dnstrap_proc_root);
  }
}