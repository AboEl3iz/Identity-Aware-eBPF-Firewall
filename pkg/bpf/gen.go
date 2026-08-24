package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf xdp ../../bpf/xdp_firewall.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu -O2 -g -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tc ../../bpf/tc_firewall.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu -O2 -g -Wall
