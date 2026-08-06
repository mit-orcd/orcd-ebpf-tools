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
 *
 */
SEC("lsm/path_chmod")
int BPF_PROG(restrict_chmod_other_bits, const struct path *path, umode_t mode,
             int ret) {

  __u32 uid;

  // to do: unstrict mode that doesn't fail as long as new file restrictions
  // are less than or equal to previous file restrictions
  // umode_t current_mode = 07777;
  // struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
  // current_mode = BPF_CORE_READ(inode, i_mode) & 07777;

  // do nothing if already denied by another LSM
  if (ret != 0)
    return ret;

  // always allow whitelist
  uid = (__u32)bpf_get_current_uid_gid();
#pragma unroll
  for (int i = 0; i < ALLOWED_COUNT; i++) {
    if (whitelist[i] == uid)
      return 0;
  }

  // deny if the requested chmod mode has any "other" permission bits.

  if (mode & bmask)
    return -EPERM;

  return 0;
}