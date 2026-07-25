package main

//go:generate go tool bpf2go -tags linux chmodblock bpf/restrict_chmod.c
