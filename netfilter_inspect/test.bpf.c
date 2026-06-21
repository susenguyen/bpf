#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/ipt_do_table")
int test(struct pt_regs *ctx) {
	bpf_printk("STEPH: testing bpf");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
