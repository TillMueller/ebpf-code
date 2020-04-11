#include <stdio.h>
#include <unistd.h>
#include <bpf.h>
#include <libbpf.h>
#include "common_kern_user.h"

#define MAX_PATH_LENGTH 4096

int main(int argc, char* argv[]) {
    int mapfd;
    char path[MAX_PATH_LENGTH];
    snprintf(path, MAX_PATH_LENGTH, "/sys/fs/bpf/%s/xdp_stats_map", argv[1]);
    mapfd = bpf_obj_get(path);
    if(mapfd < 0) {
        printf("Could not get map file descriptor, exiting\n");
        return 1;
    }
    for(;;) {
        usleep(1000000);
        __u32 key = XDP_PASS;
        struct datarec value;
        int error = bpf_map_lookup_elem(mapfd, &key, &value);
        if(error != 0) {
            printf("Could not get value from map, exiting\n");
            return 1;
        }
        printf("packets: %lld\n", value.rx_packets);
    }
}