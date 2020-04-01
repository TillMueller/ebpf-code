/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	//unsigned char* data_end = (void *)(long)ctx->data_end;

	unsigned char tmp;
	for(int i = 0; i < 6; i++) {
		tmp = data[i];
		data[i] = data[i + 6];
		data[i + 6] = tmp;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
