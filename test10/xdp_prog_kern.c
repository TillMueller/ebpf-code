/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

#include "common_kern_user.h"

struct bpf_map_def __attribute__ ((section ("maps"))) xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(struct datarec),
	.max_entries = 1,
};

__attribute__ ((section ("xdp_stats1")))
int  xdp_stats1_func(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;
	struct datarec *rec;
	int key = 0;
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	__sync_fetch_and_add(&rec->rx_packets, 1);

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