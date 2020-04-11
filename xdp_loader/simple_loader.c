#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h>
#include <bpf.h>
#include <libbpf.h>
#include <getopt.h>

enum action{NONE, LOAD, UNLOAD};

#define PATH_MAX_LENGTH 4096
#define PIN_BASE_DIR "/sys/fs/bpf"

int main (int argc, char* argv[]) {
    char* devicename = NULL;
    char* filename = NULL;
    enum action action = NONE;
    bool map = false;
    char c;
    while((c = getopt(argc, argv, "d:f:luhm")) != -1) {
        switch(c) {
            case 'd':
                devicename = optarg;
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
            case 'm':
                map = true;
                break;
            case 'h':
                printf("Usage: ./simple_loader -d <device> [-f <filename>] {-l | -u} [-m]\n");
                return 0;
        }
    }
    int ifindex;
    switch (action) {
        case NONE:
            printf("No action given, exiting\n");
            return 1;
        case LOAD:
            if (filename == NULL || devicename == NULL) {
                printf("No filename or device given, exiting\n");
                return 1;
            }
            ifindex = if_nametoindex(devicename);
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
            if(map) {
                int pathlength;
                char pin_dir_name[PATH_MAX_LENGTH];
                pathlength = snprintf(pin_dir_name, PATH_MAX_LENGTH, "%s/%s", PIN_BASE_DIR, devicename);
                if(pathlength < 0) {
                    printf("Could not generate directory name for map pinning, exiting\n");
                    return bpf_set_link_xdp_fd(ifindex, -1, 0);
                }
                bpf_object__unpin_maps(bpf_obj, pin_dir_name);
                error = bpf_object__pin_maps(bpf_obj, pin_dir_name);
                if(error) {
                    printf("Could not pin maps, exiting\n");
                    return bpf_set_link_xdp_fd(ifindex, -1, 0);
                }
            }
            break;
        case UNLOAD:
            if (devicename == NULL) {
                printf("No device given, exiting\n");
                return 1;
            }
            ifindex = if_nametoindex(devicename);
            if(ifindex == 0) {
                printf("Device not found, exiting\n");
                return 1;
            }
            error = bpf_set_link_xdp_fd(ifindex, -1, 0);
            if(error) {
                printf("Could not unload program from device, exiting\n");
                return 1;
            }
            /*
            We do not clean up maps at the moment. Unlink(3) might be enough here,
            but the canon way is using bpf_object__unpin_maps - which is unfortunate because
            it requires the bpf_object we can (as far as I can tell) only obtain by doing
            bpf_prog_load again, but then we'll need the filename for unloading, which is stupid
            so all in all - whatever
            */
            break;
    }
}
