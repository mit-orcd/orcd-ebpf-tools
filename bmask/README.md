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

1. Flexible multi-user whitelist: currently, the whitelist is hardcoded in restrict_chmod.c. A cleaner solution is to use a bpf map and populate it from main.go



