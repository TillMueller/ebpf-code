#include <linux/bpf.h>
#include <bpf_helpers.h>

#ifndef BYTES
#define BYTES 0
#endif

struct bpf_map_def SEC("maps") xdp_loop_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(unsigned char),
	.max_entries = 1,
};


SEC("xdp")
int  xdp_prog_loop(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	if(data + BYTES > data_end)
		return XDP_ABORTED;

	int key = 0;
	unsigned char* val = bpf_map_lookup_elem(&xdp_loop_map, &key);
	if(!val)
		return XDP_ABORTED;

	#pragma unroll
	for(int i = 0; i < BYTES; i++) {
		*val = data[i];
	}

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
