# Generating the vmlinux.h file
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
