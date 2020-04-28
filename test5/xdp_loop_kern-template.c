/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

#define BYTES /*{%BYTE_COUNT%}*/0

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

	unsigned char xor = 0;

	#pragma unroll
	for(int i = 0; i < BYTES; i++) {
		if(data + i > data_end)
			return XDP_ABORTED;
		xor += data[i];
	}

	int key = 0;
	unsigned char* val = bpf_map_lookup_elem(&xdp_loop_map, &key);
	if(!val)
		return XDP_ABORTED;
	*val = xor;

	unsigned char tmp;
	for(int i = 0; i < 6; i++) {
		if(data + i + 8 > data_end)
			return XDP_ABORTED;
		tmp = data[i];
		data[i] = data[i + 6];
		data[i + 6] = tmp;
	}
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";