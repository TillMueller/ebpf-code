/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h" /* defines: struct datarec; */

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	unsigned char* data_end = (void *)(long)ctx->data_end;
	unsigned char* data     = (void *)(long)ctx->data;
	struct datarec *rec;
	__u32 key = XDP_TX;

	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	lock_xadd(&rec->rx_packets, 1);

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

char _license[] SEC("license") = "GPL";
