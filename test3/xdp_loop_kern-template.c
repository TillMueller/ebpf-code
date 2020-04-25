/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

struct bpf_map_def SEC("maps") xdp_loop_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(unsigned char),
	.max_entries = /*{%LOOP_COUNT%}*/0,
};

SEC("xdp")
int  xdp_prog_loop(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	#pragma unroll
	for(int i = 0; i < /*{%LOOP_COUNT%}*/0; i++) {
		if(data + i + 8 > data_end)
			return XDP_ABORTED;
		int tmp = i;
		unsigned char* val = bpf_map_lookup_elem(&xdp_loop_map, &tmp);
		if(!val)
			return XDP_ABORTED;
		*val = data[i];
		//xor ^= data[i];
	}

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