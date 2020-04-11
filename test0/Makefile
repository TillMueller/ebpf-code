xdp_return_kern : xdp_return_kern.c
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o xdp_return_kern.ll xdp_return_kern.c
	llc -march=bpf -filetype=obj -o xdp_return_kern.o xdp_return_kern.ll
