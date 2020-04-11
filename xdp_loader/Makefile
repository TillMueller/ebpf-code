# libbpf has to be built first
# gcc -Wall -Ilibbpf/src/ -Llibbpf/src/ -o simple_loader simple_loader.c -lbpf -lelf
main : simple_loader xdp_pass_kern xdp_prog_kern write_stats

simple_loader : simple_loader.c
	gcc -Wall -Ilibbpf/src/ -Llibbpf/src/ -o simple_loader simple_loader.c -lbpf -lelf

xdp_pass_kern : xdp_pass_kern.c
	clang -S -target bpf -D __BPF_TRACING__ -Ilibbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o xdp_pass_kern.ll xdp_pass_kern.c
	llc -march=bpf -filetype=obj -o xdp_pass_kern.o xdp_pass_kern.ll

xdp_prog_kern : xdp_prog_kern.c
	clang -S -target bpf -D __BPF_TRACING__ -Ilibbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o xdp_prog_kern.ll xdp_prog_kern.c
	llc -march=bpf -filetype=obj -o xdp_prog_kern.o xdp_prog_kern.ll

write_stats : write_stats.c
	gcc -Wall -Ilibbpf/src/ -Llibbpf/src/ -o write_stats write_stats.c -lbpf -lelf

clean :
	rm simple_loader
	rm write_stats
	rm *.ll
	rm *.o
