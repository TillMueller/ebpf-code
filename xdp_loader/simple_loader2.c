// https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/prog_tests/select_reuseport.c#L107
// https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/libbpf.c#L6861

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
    bool shared_map = false;
    char* shared_map_name = NULL;
    char c;
    while((c = getopt(argc, argv, "d:f:luhms:")) != -1) {
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
                if(shared_map) {
                    printf("-m and -s cannot be used together, exiting\n");
                }
                map = true;
                break;
            case 's':
                if(map) {
                    printf("-m and -s cannot be used together, exiting\n");
                }
                shared_map = true;
                shared_map_name = optarg;
                break;
            case 'h':
                printf("Usage: ./simple_loader -d <device> [-f <filename>] {-l | -u} [-m | -s <mapname>]\n");
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
            struct bpf_object* bpf_obj = bpf_object__open(filename);

            if(map || shared_map) {
                int pathlength;
                char pin_dir_name[PATH_MAX_LENGTH];
                if(shared_map) {
                    pathlength = snprintf(pin_dir_name, PATH_MAX_LENGTH, "%s/%s", PIN_BASE_DIR, shared_map_name);
                } else {
                    pathlength = snprintf(pin_dir_name, PATH_MAX_LENGTH, "%s/%s", PIN_BASE_DIR, devicename);
                }
                if(pathlength < 0) {
                    printf("Could not generate directory name for map pinning, exiting\n");
                    return 1;
                }
                if(shared_map) {
                        struct bpf_map* map;
                        bpf_map__for_each(map, bpf_obj) {
                            char pin_full_path[PATH_MAX_LENGTH];
                            int fullpathlength = snprintf(pin_full_path, PATH_MAX_LENGTH, "%s/%s", pin_dir_name, bpf_map__name(map));
                            if(fullpathlength < 0) {
                                printf("Could not generate file name for map reuse, exiting\n");
                                return 1;
                            }
                            int mapfd = bpf_obj_get(pin_full_path);
                            if(mapfd < 0) {
                                // Map is not pinned, therefore, we need to pin it now
                                printf("New pin: %s\n", pin_full_path);
                                error = bpf_map__pin(map, pin_full_path);
                                if(error) {
                                    printf("Could not pin maps, exiting\n");
                                    return 1;
                                }
                            } else {
                                // Map is already pinned, reuse the file descriptor
                                printf("Reuse pin: %d\n", mapfd);
                                error = bpf_map__reuse_fd(map, mapfd);
                                if(error) {
                                    printf("Could not reuse map fd, exiting\n");
                                    return 1;
                                }
                            }
                        }
                } else {
                    // Clean up existing maps that might interfere, errors if there are none
                    // TODO: We should check here wheather a map is pinned before trying to unpin it
                    bpf_object__unpin_maps(bpf_obj, pin_dir_name);
                    error = bpf_object__pin_maps(bpf_obj, pin_dir_name);
                    if(error) {
                        printf("Could not pin maps, exiting\n");
                        return 1;
                    }
                }
            }
            struct bpf_program* prog, *first_prog = NULL;
            bpf_object__for_each_program(prog, bpf_obj) {
                if(!first_prog)
                    first_prog = prog;
                bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
                bpf_program__set_expected_attach_type(prog, BPF_PROG_TYPE_XDP);
            }
            error = bpf_object__load(bpf_obj);
            if(error) {
                printf("Could not load bpf object, exiting\n");
                return 1;
            }
            error = bpf_set_link_xdp_fd(ifindex, bpf_program__fd(first_prog), 0);
            if(error) {
                printf("Could not attach program to device, exiting\n");
                return 1;
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
