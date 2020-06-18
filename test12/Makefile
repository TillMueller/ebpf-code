NAME=xdp_loop_kern
BYTES=0
IF=lo
.PHONY: load unload build dump clean FORCE

load: $(NAME).o
	../xdp_loader/simple_loader -d $(IF) -f $(NAME).o -l

$(NAME).o: $(NAME).c FORCE
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -DBYTES=$(BYTES) -c -g -o $(NAME).ll $(NAME).c
	llc -march=bpf -filetype=obj -o $(NAME).o $(NAME).ll

unload:
	../xdp_loader/simple_loader -d $(IF) -u

build: $(NAME).o

dump: $(NAME).o
	llvm-objdump -S -no-show-raw-insn $(NAME).o

FORCE:

clean:
	rm $(NAME).ll
	rm $(NAME).o