/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

struct bpf_map_def __attribute__ ((section ("maps"))) xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = 1,
};

__attribute__ ((section ("xdp_stats1")))
int  xdp_stats1_func(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;
	int key = 0;
	int* val = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!val)
		return XDP_ABORTED;

	__sync_fetch_and_add(val, 1);

	unsigned char tmp;
	for(int i = 0; i < 6; i++) {
		if(data + i + 8 > data_end)
			return XDP_DROP;
		tmp = data[i];
		data[i] = data[i + 6];
		data[i + 6] = tmp;
	}
	return XDP_TX;
}

char _license[] __attribute__ ((section ("GPL"))) = "GPL";