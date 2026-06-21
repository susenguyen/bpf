# bpf
Sample programs written in BPF

## netfilter_inspect
Rewrite of the kernel module kret_probe using BPF
- Loading ```sudo bpftool prog load test.bpf.o /sys/fs/bpf/test```
