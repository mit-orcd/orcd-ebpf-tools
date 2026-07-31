# eBPF Scripts for HPC

This is (the start of) a collection of useful eBPF scripts for instrumenting HPCs 

**nfstop**: a top(1)-like, lightweight tool for analyzing NFS operations and answering questions about client access. It is especially useful for identifying clients that are generating substantial I/O.

**nfsgraf**: captures client access metrics over a short time interval and prints them to stdout. The output can be parsed as CSV for use as input to Telegraf.

**bmask**: a block mask tool to prevent regular users from changing file permissions. Our use case is to prevent users from unintentionally granting "other" bits to their files.