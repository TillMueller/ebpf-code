#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

// so we can quickly switch this to XDP_TX
#define PASS_VALUE XDP_PASS

// threshold in bits per second
#define THRESHOLD 1024

#define NANOSECONDS_PER_SECOND 1000000000

struct flow {
	uint64_t time;
	uint64_t bytes;
};

struct bpf_map_def SEC("maps") xdp_flows_bandwidth = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__uint128_t),
	.value_size  = sizeof(struct flow),
	// this probably is not enough but should be sufficient for testing
	.max_entries = 65536,
};

enum l4protocol {NONE, TCP, UDP};

SEC("xdp")
int  xdp_stats(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	volatile int length = data_end - data;
	if(data_end < data || length == 0)
		return XDP_ABORTED;
	
	struct ethhdr* ethhdr = (void*) &data[0];
    int total_size = sizeof(struct ethhdr);

    if(data + total_size > data_end)
        return XDP_DROP;
    
	// only filter IPv4 for now
    if(ethhdr->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr* iphdr = (void*) &data[total_size];
    total_size += sizeof(struct iphdr);

    if(data + total_size > data_end)
        return XDP_DROP;
	
	uint32_t src_ip = iphdr->saddr;
	uint32_t dst_ip = iphdr->daddr;
	
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	enum l4protocol l4protocol = NONE;

	switch(iphdr->protocol) {
		case IPPROTO_UDP: {
			struct udphdr* udphdr = (void*) &data[total_size];
			total_size += sizeof(struct udphdr);

			if(data + total_size > data_end)
				return XDP_DROP;
			
			src_port = ntohs(udphdr->source);
			dst_port = ntohs(udphdr->dest);
			l4protocol = UDP;
			break;
		}
		case IPPROTO_TCP: {
			struct tcphdr* tcphdr = (void*) &data[total_size];
			total_size += sizeof(struct tcphdr);

			if(data + total_size > data_end)
				return XDP_DROP;
			
			src_port = ntohs(tcphdr->source);
			dst_port = ntohs(tcphdr->dest);
			l4protocol = TCP;
			break;
		}
	}

	// only filter known protocols
	if(l4protocol == NONE)
		return XDP_PASS;
	
	// key is of this format:
	__uint128_t key = ((__uint128_t) src_ip << 96) + ((__uint128_t) dst_ip << 64) + ((__uint128_t) src_port << 48) + ((__uint128_t) dst_port << 32) + l4protocol;

	uint64_t curtime = bpf_ktime_get_ns();

	struct flow* val = bpf_map_lookup_elem(&xdp_flows_bandwidth, &key);
	if (!val) {
		struct flow new = {};
		new.time = curtime;
		new.bytes = length;
		int error = bpf_map_update_elem(&xdp_flows_bandwidth, &key, &new, BPF_ANY);
		if(error)
			return XDP_ABORTED;
		return PASS_VALUE;
	}

	if(val->bytes == 0) {
		val->time = curtime;
		val->bytes = length;
		return PASS_VALUE;
	}

	uint64_t delta = curtime - val->time;
	uint64_t bitspersecond = (((val->bytes + length) * 8 * NANOSECONDS_PER_SECOND) / delta);

	// if one second has passed since this flow started, we get rid of it
	if(delta >= NANOSECONDS_PER_SECOND) {
		val->time = curtime;
		val->bytes = 0;
	}

	if(bitspersecond >= THRESHOLD) {
		return XDP_DROP;
	}

	// we might need __sync_fetch_and_add here
	__sync_fetch_and_add(&val->bytes, length);
	return PASS_VALUE;
}

char _license[] SEC("license") = "GPL";