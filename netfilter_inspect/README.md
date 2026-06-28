# Refactoring my kretprobe using BPF

- https://github.com/susenguyen/netfilter_inspect

## Requires
- kernel sources
- make headers_install
- clang, llvm
- bpftool

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
