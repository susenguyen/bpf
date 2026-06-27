#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>	/* For bpf_ntohs() and bpf_ntohl	*/

/*
 *===== BEGIN ======
 *
 * Definition of macros and inline functions not available in BTF
 *
 */

#define NF_ACCEPT 1		/* From uapi/linux/netfilter.h		*/

/*
 * ip_hdr()
 *
 */
static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

/*
 * tcp_hdr() & udp_hdr()
 *
 */
static inline bool skb_transport_header_was_set(const struct sk_buff *skb)
{
	return skb->transport_header != (typeof(skb->transport_header))~0U;
}

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	// NMS DEBUG_NET_WARN_ON_ONCE(!skb_transport_header_was_set(skb));
	return skb->head + skb->transport_header;
}

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}


/*
 * struct xt_table
 *
 * Took some shortcuts because all we need is xt_table->name...
 *
 */

#define XT_TABLE_MAXNAMELEN 32

struct xt_table {
	struct list_head list;
	unsigned int valid_hooks;
	struct xt_table_info *private;
	struct nf_hook_ops *ops;
	struct module *me;
	u_int8_t af;
	int priority;
	const char name[XT_TABLE_MAXNAMELEN];
};

struct xt_table_info {
	unsigned int size;
	unsigned int number;
	unsigned int initial_entries;
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];
	unsigned int stacksize;
	void ***jumpstack;

	unsigned char entries[]; /* NMS removed the __aligned() clause not needed here */
};

/*
 * ===== END =====
 *
 * Definition of macros and inline functions not available in BTF
 *
 */

SEC("fexit/ipt_do_table")
int BPF_PROG(ipt_do_table_exit, void *priv, struct sk_buff *skb, const struct nf_hook_state *state, unsigned int ret)
{
	struct xt_table *table = priv;



	unsigned int verdict;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	__u32 saddr, daddr;
	__u16 src, dst;
	unsigned int proto;
	const char *devin, *devout;
	int devidxin, devidxout;

	verdict = ret;

	/* We don't care about accepted packets so exit quickly */
	if (verdict == NF_ACCEPT)
		return 0;

	/* Initialize the devices & indexes */
	devin = NULL;
	devidxin = 0;
	devout = NULL;
	devidxout = 0;

	iph = ip_hdr(skb);
	if (!iph) {
		bpf_printk("%s: failed to find the iphdr structure", __func__);
		return 0;
	}

	saddr = bpf_ntohl(iph->saddr);
	daddr = bpf_ntohl(iph->daddr);

	switch(iph->protocol) {
		case IPPROTO_TCP:
		       	tcph = tcp_hdr(skb);

			if (!tcph) {
				bpf_printk("%s: failed to find the tcphdr structure", __func__);
				return 0;
			}

			proto = 0x000000ff & IPPROTO_TCP;
			src = bpf_ntohs(tcph->source);
			dst = bpf_ntohs(tcph->dest);

			break;
		case IPPROTO_UDP:
			udph = udp_hdr(skb);

			if (!udph) {
				bpf_printk("%s: failed to find the udph structure", __func__);
				return 0;
			}

			proto = 0x000000ff & IPPROTO_UDP;
			src = __bpf_ntohs(udph->source);
			dst = __bpf_ntohs(udph->dest);

			break;
		default:
			bpf_printk("[ipt_do_table_exit()]: unsupported L4 protocol; only TCP and UDP are supported");
			return 0;
	}

	if (state) {
		if (state->in) {
			devin = state->in->name;
			devidxin = state->in->ifindex;
		}

		if (state->out) {
			devout = state->out->name;
			devidxout = state->out->ifindex;
		}
	}

	bpf_printk("ipt_do_table_exit()(%s) - devin=%s/%d, devout=%s/%d, saddr=0x%x, daddr=0x%x, proto=%s, "
		"spt=0x%x, dpt=0x%x, verdict=0x%x\n", table->name, devin,
					devidxin, devout, devidxout, saddr, daddr,
					proto == IPPROTO_TCP ? "tcp" : "udp",
					src, dst, verdict);




	//bpf_printk("STEPH: skb @%p, state @%p, table @%p", skb, state, priv);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
