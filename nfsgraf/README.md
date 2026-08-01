## Installing eBPF tools

You will need to install `bpftrace` and the appropriate Kernel headers on your system. On Red Hat-likes:

```
dnf install bpftrace kernel-headers-$(uname -r)
```

## Design of the scripts
These scripts are intended to produce output that can be easily scraped by shell tools and forwarded to central collector systems (such as Telegraf). 

## Running the scripts
You can either run the scripts as standalone scripts (i.e., `./nfsd.bt`) or invoke the `bpftrace` tool (e.g. `bpftrace nfsd.bt`). 

To parse it in CSV format to be used by Telegraf, you can use the `./collect-bpf-nfsd.sh` script.

These sample the various tracepoints for a short interval (10s by default), such that they can be executed on a cron or another similar tool. 
