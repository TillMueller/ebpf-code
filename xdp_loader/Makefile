# libbpf has to be built first
main : simple_loader

simple_loader : simple_loader2.c
	gcc -Wall -Ilibbpf/src/ -Llibbpf/src/ -o simple_loader simple_loader2.c -lbpf -lelf

clean :
	rm simple_loader
