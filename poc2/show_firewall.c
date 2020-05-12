#include <stdio.h>
#include <unistd.h>
#include <bpf.h>
#include <libbpf.h>
#include <stdbool.h>

#define MAX_PATH_LENGTH 4096

int main(int argc, char* argv[]) {
    int mapfd;
    char path[MAX_PATH_LENGTH];
    snprintf(path, MAX_PATH_LENGTH, "/sys/fs/bpf/%s/xdp_firewall_rules_map", argv[1]);
    mapfd = bpf_obj_get(path);
    if(mapfd < 0) {
        printf("Could not get map file descriptor, exiting\n");
        fflush(stdout);
        return 1;
    }

    for(;;) {
        usleep(1000000);
        for(int i = 0; i < 65536; i++) {
            bool value;
            int error = bpf_map_lookup_elem(mapfd, &i, &value);
            if(error) {
                printf("Could not get value (%d) from map, exiting\n", i);
                fflush(stdout);
                return 1;
            }
            if(value) {
                printf("%d BLOCKED\n", i);
            }
        }
        printf("\n");
        fflush(stdout);
    }
}