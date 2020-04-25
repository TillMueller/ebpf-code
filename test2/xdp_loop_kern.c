/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("xdp")
int  xdp_prog_loop(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	unsigned char xor = 0;

	#pragma unroll
	for(int i = 0; i < 60; i++) {
		if(data + i > data_end)
			break;
		xor ^= data[i];
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
