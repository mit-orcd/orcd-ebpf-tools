## Overview

bmask prevents non-root users from changing file permission bits. It achieves so by hooking an eBPF program to the security module lsm/path_chmod. If it any of the bits specified in bmask is attempted modificiation, and the user is not root, then chmod fails with EPERM. 

## Install

Obtain vmlinux.h
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

Generate boilerplate for cilium/ebpf
```bash
go generate && go build
```

## Usage

```bash
BMASK=0007 ./bmask
```

## To do and ideas

1. Currently, 

## Discussion

Problem: Users can run chmod 777, making their files public to
all users, and in many cases this is not what they actually want. This is
because Linux implements a Discretionary Access Control.

Kernel Patches, such as HPCFilePermissionHandler
<https://github.com/mit-llsc/HPCFilePermissionHandler>, exist to counteract this
by implementing a strict mask; however, maintaining a custom kernel can cause
excessive maintainability burden.

Linux Security Module (LSM) is a framework that provides a mechanism for various
security checks to be hooked by new kernel extensions
<https://docs.kernel.org/admin-guide/LSM/index.html>. This allows security
modules to use the LSM framework to add their own access-control rules to the
Linux kernel. For example, SELinux, AppArmor, TOMOYO, and SMACK are secuirty
modules that implement a Mandatory Access Control (MAC).
<https://en.wikipedia.org/wiki/Mandatory_access_control#:~:text=Linux%20familyedit>

I think that none of these specifically solve our problem *only*, as in you
might be able to use them but result in stricter rules. For example, AppArmor is
profile-based, hence you could make a profile to deny chmod or setattr for all
in files inside /home; however, this would not only make chmod 777 fail, but
would make chmod unusuable system-wide.

The SMACK (Simplified Mandatory Access Control Kernel) LSM might be more useful
for this use case
<https://www.kernel.org/doc/html/v6.1/admin-guide/LSM/Smack.html>. You might be
able to prevent other users from accessing files with permissions 777, though
not explicitly prevent chmod 777 from changing the other bits. 




