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

	#pragma unroll
	for(int i = 1; i <= BYTES; i++) {
		if(data + i > data_end)
			return XDP_ABORTED;
		int tmp = i - 1;
		bpf_map_update_elem(&xdp_loop_map, &tmp, &data[i - 1], BPF_ANY);
	}

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
