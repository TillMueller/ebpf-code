/* SPDX-License-Identifier: GPL-2.0 */
#include <bpf.h>

__attribute__ ((section ("xdp")))
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_ABORTED;
}

char _license[] __attribute__ ((section ("GPL"))) = "GPL";
