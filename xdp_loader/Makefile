# libbpf has to be built first
# gcc -Wall -Ilibbpf/src/ -Llibbpf/src/ -o simple_loader simple_loader.c -lbpf -lelf
main : simple_loader

simple_loader : simple_loader.c
	gcc -Wall -Ilibbpf/src/ -Llibbpf/src/ -o simple_loader simple_loader.c -lbpf -lelf

clean :
	rm simple_loader
