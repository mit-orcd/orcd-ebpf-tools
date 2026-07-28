# NFS Traffic Viewer

## Installation

You will need a reasonably modern Golang toolchain. This software was written
against Golang v1.25, but older versions may work.

You will also need llvm, clang, and kernel headers to compile BPF programs against the running kernel.

On Red Hat variants:
```bash
yum install kernel-headers-$(uname -r) llvm clang go libbpf-devel
```

## Compiling and running 

Retrieve the appropriate BPF Type Format (BTF) dumps for your running kernel:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
bpftool btf dump file /sys/kernel/btf/nfsd format c > bpf/nfsd-btf.h
# if nfsd doesn't exist, you might have not loaded it; try `modprobe nfsd`
```

Then generate the needed boilerplate for `go-bpf` and build the viewer:

```bash
go generate && go build
```
