# Refactoring my kretprobe using BPF fexit()

- https://github.com/susenguyen/netfilter_inspect

## Requires
- kernel sources
- make headers_install
- clang, llvm
- build /usr/src/linux/tools/lib/bpf (path for openSUSE)
- bpftool
- [PROGRAM].bpf.o and [PROGRAM] must live in the same directory

## fexit() vs kretprobe
fexit() provides certain advantages over kretprobes
- faster
- holds the parameters (instead of CPU registers) which means we don't need to store the kprobe (entry) registers in a global structure (simpler)
- but requires BTF (and a "newer" kernel)

Also, both are equally dynamically instrumenting kernel functions which is not guaranteed to work with all kernel versions. In the case of ipt_do_table(), this function has be around for a veeeeery long time, so not overly worried it will change... Except for nft of course, but that will be the next challenge.

## Output

The output can be grabbed via dmesg and will look something like this

```  
ipt_do_table(filter) - devin=(null)/0, devout=eth0/2, saddr=0xa010002, daddr=0xa010001, proto=6, spt=0xb986, dpt=0x1f90, verdict=0
```

- devin: ingress device
- devout: egress device
- saddr: source IP address in little-endian (hex)
- daddr: destination IP address in little-endian (hex)
- proto: "tcp" or "udp"
- spt: source TCP/UDP port in little-endian (hex)
- dpt: destination TCP/UDP port in little-endian (hex)
- verdict: netfilter verdict NF_* which values/code mappings can be found in uapi/linux/netfilter.h
