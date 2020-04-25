NAME=xdp_return_kern
.PHONY: load unload build dump clean

load: $(NAME).o
	../xdp_loader/simple_loader -d $(IF) -f $(NAME).o -l

$(NAME).o: $(NAME).c
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $(NAME).ll $(NAME).c
	llc -march=bpf -filetype=obj -o $(NAME).o $(NAME).ll

unload:
	../xdp_loader/simple_loader -d $(IF) -u

dump: $(NAME).o
	llvm-objdump -S -no-show-raw-insn $(NAME).o

clean:
	rm $(NAME).ll
	rm $(NAME).o