main : xdp_prog_kern write_stats

xdp_prog_kern : xdp_prog_kern.c
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o xdp_prog_kern.ll xdp_prog_kern.c
	llc -march=bpf -filetype=obj -o xdp_prog_kern.o xdp_prog_kern.ll

write_stats : write_stats.c
	gcc -Wall -I../xdp_loader/libbpf/src/ -L../xdp_loader/libbpf/src/ -o write_stats write_stats.c -lbpf -lelf

clean :
	rm write_stats
	rm *.ll
	rm *.o
