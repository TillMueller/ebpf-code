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

struct map_data {
    bool alreadyPinned;
    struct bpf_map* map;
    int fd;
};

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
        case LOAD: {
            if (filename == NULL || devicename == NULL) {
                printf("No filename or device given, exiting\n");
                return 1;
            }
            ifindex = if_nametoindex(devicename);
            if(ifindex == 0) {
                printf("Device not found, exiting\n");
                return 1;
            }
            int error, pathlength;
            char pin_dir_name[PATH_MAX_LENGTH];
            struct bpf_object* bpf_obj = bpf_object__open(filename);
            if(map)
                pathlength = snprintf(pin_dir_name, PATH_MAX_LENGTH, "%s/%s", PIN_BASE_DIR, devicename);
            if(shared_map)
                pathlength = snprintf(pin_dir_name, PATH_MAX_LENGTH, "%s/%s", PIN_BASE_DIR, shared_map_name);
            if(pathlength < 0) {
                printf("Could not generate directory name for map pinning, exiting\n");
                return 1;
            }
            size_t number_of_maps = 0;
            // This array is to remember which maps we need to reuse
            // The whole reason why we need this is to avoid altering the data structure we're interating over
            struct map_data map_data[number_of_maps];
            if(shared_map) {
                // This could be O(1), but there is no obvious way to access bpf_obj->nr_maps from here
                // We could avoid this whole thing by having a linked list but I am not about to implement one
                struct bpf_map* map;
                bpf_map__for_each(map, bpf_obj) {
                    number_of_maps++;
                }
                int arrayindex = 0;
                bpf_map__for_each(map, bpf_obj) {
                    const char* map_name = bpf_map__name(map);
                    char pin_full_path[PATH_MAX_LENGTH];
                    int fullpathlength = snprintf(pin_full_path, PATH_MAX_LENGTH, "%s/%s", pin_dir_name, map_name);
                    if(fullpathlength < 0) {
                        printf("Could not generate file name for map reuse, exiting\n");
                        return 1;
                    }
                    printf("Checking if map is already pinned: %s\n", pin_full_path);
                    int mapfd = bpf_obj_get(pin_full_path);
                    if(arrayindex >= number_of_maps) {
                        printf("Found more maps than expected, exiting\n");
                        return 1;
                    }
                    if(mapfd > 0) {
                        map_data[arrayindex].fd = mapfd;
                        map_data[arrayindex].alreadyPinned = true;
                    } else {
                        map_data[arrayindex].alreadyPinned = false;
                    }
                    map_data[arrayindex].map = map;  
                    arrayindex++;
                }
                for(int i = 0; i < number_of_maps; i++) {
                    if(!map_data[i].alreadyPinned)
                        continue;
                    printf("Reusing pin: %d\n", map_data[i].fd);
                    error = bpf_map__reuse_fd(map_data[i].map, map_data[i].fd);
                    if(error) {
                        printf("Could not reuse map fd %d, exiting\n", map_data[i].fd);
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
            // Second round, pin everything we could not reuse
            if(shared_map) {
                for(int i = 0; i < number_of_maps; i++) {
                    if(map_data[i].alreadyPinned)
                        continue;
                    const char* map_name = bpf_map__name(map_data[i].map);
                    char pin_full_path[PATH_MAX_LENGTH];
                    int fullpathlength = snprintf(pin_full_path, PATH_MAX_LENGTH, "%s/%s", pin_dir_name, map_name);
                    if(fullpathlength < 0) {
                        printf("Could not generate file name for map pinning, exiting\n");
                        return 1;
                    }
                    printf("New pin: %s\n", pin_full_path);
                    error = bpf_map__pin(map_data[i].map, pin_full_path);
                    if(error) {
                        printf("Could not pin map, exiting\n");
                        return 1;
                    }
                }
            }
            if(map) {
                // Clean up existing maps that might interfere
                struct bpf_map* map;
                bpf_map__for_each(map, bpf_obj) {
                    char pin_full_path[PATH_MAX_LENGTH];
                    int fullpathlength = snprintf(pin_full_path, PATH_MAX_LENGTH, "%s/%s", pin_dir_name, bpf_map__name(map));
                    if(fullpathlength < 0) {
                        printf("Could not generate file name for map unpinning, exiting\n");
                        return 1;
                    }
                    int mapfd = bpf_obj_get(pin_full_path);
                    if(mapfd > 0) {
                        // Map is pinned, unpin it now so we can repin it
                        // This resets the map, which is what we want to for unshared ones
                        printf("Unpinning: %s\n", pin_full_path);
                        error = bpf_map__unpin(map, pin_full_path);
                        if(error) {
                            printf("Could not unpin map, exiting\n");
                            return 1;
                        }
                    } 
                }
                bpf_object__unpin_maps(bpf_obj, pin_dir_name);
                error = bpf_object__pin_maps(bpf_obj, pin_dir_name);
                if(error) {
                    printf("Could not pin maps, exiting\n");
                    return 1;
                }
            }
            break;
        }
        case UNLOAD: {
            if (devicename == NULL) {
                printf("No device given, exiting\n");
                return 1;
            }
            ifindex = if_nametoindex(devicename);
            if(ifindex == 0) {
                printf("Device not found, exiting\n");
                return 1;
            }
            int error = bpf_set_link_xdp_fd(ifindex, -1, 0);
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
}
