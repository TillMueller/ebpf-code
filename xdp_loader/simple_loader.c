#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf.h>
#include <libbpf.h>
//#include "bpf.h"
//#include "libbpf.h"

enum action{NONE, LOAD, UNLOAD};

int main (int argc, char* argv[]) {
    char* device = NULL;
    char* filename = NULL;
    enum action action = NONE;
    int c;
    while((c = getopt(argc, argv, "d:f:luh")) != -1) {
        switch(c) {
            case 'd':
                device = optarg;
                break;
            case 'f':
                filename = optarg;
                break;
            case 'l':
                if(action != NONE) {
                    printf("Multiple loading / unloading commands given, exiting\n");
                    return 1;
                }
                action = LOAD;
                break;
            case 'u':
                if(action != NONE) {
                    printf("Multiple loading / unloading commands given, exiting\n");
                    return 1;
                }
                action = UNLOAD;
                break;
            case 'h':
                printf("Usage: ./simple_loader -d <device> [-f <filename>] {-l | -u}\n");
                return 0;
        }
    }
    int ifindex;
    switch (action) {
        case NONE:
            printf("No action given, exiting\n");
            return 1;
        case LOAD:
            if (filename == NULL || device == NULL) {
                printf("No filename or device given, exiting\n");
                return 1;
            }
            ifindex = if_nametoindex(device);
            if(ifindex == 0) {
                printf("Device not found, exiting\n");
                return 1;
            }
            int error;
            int fd = -1;
            struct bpf_object* bpf_obj;

            error = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &bpf_obj, &fd);
            if(error) {
                printf("Could not load file, exiting\n");
                return 1;
            }
            error = bpf_set_link_xdp_fd(ifindex, fd, 0);
            if(error) {
                printf("Could not attach program to device, exiting\n");
                return 1;
            }
            break;
        case UNLOAD:
            if (device == NULL) {
                printf("No device given, exiting\n");
                return 1;
            }
            ifindex = if_nametoindex(device);
            if(ifindex == 0) {
                printf("Device not found, exiting\n");
                return 1;
            }
            error = bpf_set_link_xdp_fd(ifindex, -1, 0);
            if(error) {
                printf("Could not unload program from device, exiting\n");
                return 1;
            }
            break;
    }
}