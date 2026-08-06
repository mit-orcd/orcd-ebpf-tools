## Overview

bmask prevents non-root users from changing specific file permission bits. It achieves so by hooking an eBPF program to the security module lsm/path_chmod. If any of the bits specified in bmask is attempted modificiation, and the user is not root, then chmod fails with EPERM. 

In summary:
```
if (requested_mod & BMASK != 0) return -EPERM;
```
By default BMASK=0002, meaning it will block write permissions to other.

## Usage as systemd service

The RPM sets up bmask as a systemd service. Download it and install it with `dnf install <rpm_package>`

You can access the environment files at `/etc/sysconfig/bmask` and configure BMASK as desired.

Start the service as usual `systemctl enable --now bmask`.

**Building RPM from source**: `make rpm` (uses build machine environment) or `make mock` (uses mock to build in a fresh chroot)

## Usage as standalone program

Run `make build` to only build the ebpf-go program. 

Then run the program to load into the kernel `BMASK=0002 ./bmask`

`make build` is equivalent to:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
go generate && go build
```

## To do and ideas

1. Flexible multi-user whitelist: currently, the whitelist is hardcoded in restrict_chmod.c 
2. Implement a non-strict mode as default: don't fail if the current file permissions already had a blocked permission set
3. Log failed attempts to chmod with path addresses
4. Add ways to restrict to specific files
