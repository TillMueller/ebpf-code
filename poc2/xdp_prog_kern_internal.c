#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>

struct cmd_data {
	uint8_t response_code;
	uint8_t command;
	uint16_t argument;
};

struct bpf_map_def SEC("maps") xdp_firewall_rules_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(bool),
	.max_entries = 65536,
};

#define DEFAULT_ACTION XDP_PASS

SEC("xdp")
int xdp_firewall_internal(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

    struct ethhdr* ethhdr = (void*) &data[0];
    int total_size = sizeof(struct ethhdr);

    if(data + total_size > data_end)
        return DEFAULT_ACTION;
    
    if(ethhdr->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr* iphdr = (void*) &data[total_size];
    total_size += sizeof(struct iphdr);

    if(data + total_size > data_end)
        return DEFAULT_ACTION;

    if(iphdr->protocol != IPPROTO_UDP)
        return DEFAULT_ACTION;
    
	struct udphdr* udphdr = (void*) &data[total_size];
	total_size += sizeof(struct udphdr);

    if(data + total_size > data_end)
        return DEFAULT_ACTION;
    
    if(udphdr->dest != htons(4242))
        return DEFAULT_ACTION;
	
	struct cmd_data* cmd_data = (void*) &data[total_size];
	total_size += sizeof(struct cmd_data);

	if(data + total_size > data_end)
        return DEFAULT_ACTION;

	if(cmd_data->command > 1)
		return DEFAULT_ACTION;

	int key = ntohs(cmd_data->argument);
	bool* val = bpf_map_lookup_elem(&xdp_firewall_rules_map, &key);
	if (!val)
		return XDP_ABORTED;
	
	//command: 0 -> block; 1 -> allow
	*val = (cmd_data->command & 1);

	//command was successful
	//TODO maybe we should send something back for some cases where it was not
	cmd_data->response_code = 1;

    //switch src and dst macs
	#pragma unroll
	for(int i = 0; i < 6; i++) {
		unsigned char tmp = ethhdr->h_dest[i];
		ethhdr->h_dest[i] = ethhdr->h_source[i];
		ethhdr->h_source[i] = tmp;
	}

    //switch src and dst ips
    __u32 ip_saddr = iphdr->saddr;
    iphdr->saddr = iphdr->daddr;
    iphdr->daddr = ip_saddr;

	//switch src and dst ports
	uint16_t udp_source = udphdr->source;
	udphdr->source = udphdr->dest;
	udphdr->dest = udp_source;

	//TODO recalculate checksum

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";