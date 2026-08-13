// restrict_chmod.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char __license[] SEC("license") = "GPL";

// modified from userspace by setting env variables
const volatile __u32 bmask = 0002;
const volatile __u32 strict = 0;

// list of allowed uids that can always use chmod
const __u32 whitelist[] = {0}; // modify as needed
#define ALLOWED_COUNT (sizeof(whitelist) / sizeof(whitelist[0]))

/*
 * Deny chmod/fchmod/fchmodat attempts that set permission bits prohibitted by
 * bmask: lsm/path_chmod hooks to the security_path_chmod function
 * https://github.com/torvalds/linux/blob/0e35b9b6ec0ffcc5e23cbdec09f5c622ad532b53/security/security.c#L1577
 *
 * Notice that the operation will fail loudly.
 */
SEC("lsm/path_chmod")
int BPF_PROG(restrict_chmod_other_bits, const struct path *path, umode_t mode,
             int ret) {

  bpf_printk("Hooked to lsm/path_chmod.\n");
  // do nothing if already denied by another LSM
  if (ret != 0)
    return ret;

  // always allow whitelist
  __u32 uid = (__u32)bpf_get_current_uid_gid();
#pragma unroll
  for (int i = 0; i < ALLOWED_COUNT; i++) {
    if (whitelist[i] == uid)
      return 0;
  }

  struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
  umode_t current_mode = BPF_CORE_READ(inode, i_mode) & 07777;
  umode_t mode_delta = (mode ^ current_mode) & mode;

  /*
  strict: always make sure the end permission does not contain bits in bmask
      `chmod u+x <file>` fails with BMASK=0007, UMASK=0022 (744 & 007 != 0)
  nonstrict: only check with the permission bits that changed (mode_delta)
      `chmod u+x <file>` succeeds with BMASK=0007, UMASK=0022 (100 & 007 == 0)
  */

  switch (strict) {
  default:

    if (mode_delta & bmask) {
      // bpf_printk("NONSTRICT: new_mode=%u, current_mode=%u, bmask=%u\n", mode,
      //            current_mode, bmask);
      // bpf_printk("NONSTRICT values: xor=%u, delta_mode=%u, res=%u\n",
      //            mode ^ current_mode, mode_delta, mode_delta & bmask);

      return -EPERM;
    }

    break;

  case 1:
    if (mode & bmask) {
      // bpf_printk("STRICT: new_mode=%u, current_mode=%u, bmask=%u\n", mode,
      //            current_mode, bmask);
      return -EPERM;
    }
    break;
  }

  bpf_printk("VALID: new_mode=%u, current_mode=%u, bmask=%u\n", mode,
             current_mode, bmask);

  return 0;
}
