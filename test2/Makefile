xdp_loop_kern : xdp_loop_kern.c
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o xdp_loop_kern.ll xdp_loop_kern.c
	llc -march=bpf -filetype=obj -o xdp_loop_kern.o xdp_loop_kern.ll
