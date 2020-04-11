/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

#include "common_kern_user.h"

struct bpf_map_def __attribute__ ((section ("maps"))) xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

__attribute__ ((section ("xdp_stats1")))
int  xdp_stats1_func(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 key = XDP_PASS;
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	__sync_fetch_and_add(&rec->rx_packets, 1);
	return XDP_PASS;
}

char _license[] __attribute__ ((section ("GPL"))) = "GPL";