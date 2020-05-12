#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

struct bpf_map_def SEC("maps") xdp_firewall_rules_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(uint16_t),
	.value_size  = sizeof(bool),
	.max_entries = 65536,
};

SEC("xdp")
int xdp_firewall_external(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

    struct ethhdr* ethhdr = (void*) &data[0];
    int total_size = sizeof(struct ethhdr);

    if(data + total_size > data_end)
        return XDP_DROP;
    
	// only firewall IPv4 for now
    if(ethhdr->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr* iphdr = (void*) &data[total_size];
    total_size += sizeof(struct iphdr);

    if(data + total_size > data_end)
        return XDP_DROP;
	
	uint16_t port = 0;

	switch(iphdr->protocol) {
		case IPPROTO_UDP: {
			struct udphdr* udphdr = (void*) &data[total_size];
			total_size += sizeof(struct udphdr);

			if(data + total_size > data_end)
				return XDP_DROP;
			
			port = ntohs(udphdr->dest);
			break;
		}
		case IPPROTO_TCP: {
			struct tcphdr* tcphdr = (void*) &data[total_size];
			total_size += sizeof(struct tcphdr);

			if(data + total_size > data_end)
				return XDP_DROP;
			
			port = ntohs(tcphdr->dest);
			break;
		}
	}

	if(!port)
		return XDP_ABORTED;

	bool* val = bpf_map_lookup_elem(&xdp_firewall_rules_map, &port);
	if (!val)
		return XDP_ABORTED;

	if(*val) {
		return XDP_PASS;
	} else {
		return XDP_DROP;
	}

	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";