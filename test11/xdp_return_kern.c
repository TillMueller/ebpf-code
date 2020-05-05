/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("xdp")
int  xdp_prog_return(struct xdp_md *ctx) {
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
