#include <linux/bpf.h>
#include <bpf_helpers.h>

#ifndef BYTES
#define BYTES 0
#endif

SEC("xdp")
int  xdp_prog_loop(struct xdp_md *ctx) {
	unsigned char* data = (void *)(long)ctx->data;
	unsigned char* data_end = (void *)(long)ctx->data_end;

	#pragma unroll
	for(int i = 0; i < BYTES; i++) {
		if(data + i > data_end)
			return XDP_ABORTED;
	}

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
