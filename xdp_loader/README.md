# Make libbpf first

sudo LD_LIBRARY_PATH=$PWD/libbpf/src:$LD_LIBRARY_PATH ./simple_loader -d veth -f xdp_pass_kern.o -l

sudo LD_LIBRARY_PATH=$PWD/libbpf/src:$LD_LIBRARY_PATH ./simple_loader -d veth -u
