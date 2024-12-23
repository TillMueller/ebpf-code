#include <linux/bpf.h>
#include <bpf_helpers.h>

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(long long unsigned int),
	.max_entries = 256,
};

SEC("xdp")
int xdp_stats(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	int length = data_end - data;
	if(data_end < data || length == 0 || length > 256)
		return XDP_ABORTED;

	int key = length - 1;
	long long unsigned int* val = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!val)
		return XDP_ABORTED;

	__sync_fetch_and_add(val, 1);
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";