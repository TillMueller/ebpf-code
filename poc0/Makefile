NAME=xdp_prog_kern
NAME_USER=write_stats
IF=lo
.PHONY: load unload build dump clean

load: $(NAME).o $(NAME_USER)
	../xdp_loader/simple_loader -d $(IF) -f $(NAME).o -l -m
	sleep 3
	./write_stats $(IF)

$(NAME).o: $(NAME).c
	clang -S -target bpf -D __BPF_TRACING__ -I../xdp_loader/libbpf/src/ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $(NAME).ll $(NAME).c
	llc -march=bpf -filetype=obj -o $(NAME).o $(NAME).ll

$(NAME_USER): $(NAME_USER).c
	gcc -Wall -I../xdp_loader/libbpf/src/ -L../xdp_loader/libbpf/src/ -o $(NAME_USER) $(NAME_USER).c -lbpf -lelf

unload:
	../xdp_loader/simple_loader -d $(IF) -u

build: $(NAME).o

dump: $(NAME).o
	llvm-objdump -S -no-show-raw-insn $(NAME).o

clean:
	rm $(NAME_USER)
	rm $(NAME).ll
	rm $(NAME).o