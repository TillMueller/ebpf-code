NAME=xdp_prog_kern_external
NAME2=xdp_prog_kern_internal
NAME_USER=show_firewall
IF=enp5s0f1
IF2=lo
MAPNAME=shared_firewall
.PHONY: load unload build dump clean

load: $(NAME).o $(NAME2).o
	../xdp_loader/simple_loader -d $(IF) -f $(NAME).o -l -s $(MAPNAME)
	../xdp_loader/simple_loader -d $(IF2) -f $(NAME2).o -l -s $(MAPNAME)

unload:
	../xdp_loader/simple_loader -d $(IF) -u
	../xdp_loader/simple_loader -d $(IF2) -u

$(NAME).o $(NAME2).o: $(NAME).c $(NAME2).c
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $(NAME).ll $(NAME).c
	llc -march=bpf -filetype=obj -o $(NAME).o $(NAME).ll
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $(NAME2).ll $(NAME2).c
	llc -march=bpf -filetype=obj -o $(NAME2).o $(NAME2).ll

$(NAME_USER): $(NAME_USER).c
	gcc -Wall -I../xdp_loader/libbpf/src/ -L../xdp_loader/libbpf/src/ -o $(NAME_USER) $(NAME_USER).c -lbpf -lelf

build: $(NAME).o $(NAME2).o

dump: $(NAME).o $(NAME2).o
	llvm-objdump -S -no-show-raw-insn $(NAME).o
	llvm-objdump -S -no-show-raw-insn $(NAME2).o

clean:
	rm $(NAME_USER)
	rm $(NAME).ll
	rm $(NAME).o
	rm $(NAME2).ll
	rm $(NAME2).o