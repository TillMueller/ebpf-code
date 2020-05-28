#include <linux/bpf.h>
#include <bpf_helpers.h>

#ifndef BYTES
#define BYTES 0
#endif

struct bpf_map_def SEC("maps") xdp_loop_map = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(int),
	.value_size  = sizeof(unsigned char),
	.max_entries = BYTES,
};

SEC("xdp")
int  xdp_prog_loop(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	unsigned char init_val = 0;

	if(data + BYTES > data_end)
		return XDP_ABORTED;

	#pragma unroll
	for(int i = 1; i <= BYTES; i++) {
		int tmp = i - 1;
		unsigned char* val = bpf_map_lookup_elem(&xdp_loop_map, &tmp);
		if(!val) {
			bpf_map_update_elem(&xdp_loop_map, &tmp, &init_val, BPF_ANY);
			val = bpf_map_lookup_elem(&xdp_loop_map, &tmp);
			if(!val)
				return XDP_ABORTED;
		}
		*val = data[i - 1];
	}

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
