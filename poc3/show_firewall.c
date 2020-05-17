#include <stdio.h>
#include <unistd.h>
#include <bpf.h>
#include <libbpf.h>
#include <stdbool.h>

#define MAX_PATH_LENGTH 4096

struct flow {
	uint64_t time;
	uint64_t bytes;
};

int main(int argc, char* argv[]) {
    int mapfd;
    char path[MAX_PATH_LENGTH];
    snprintf(path, MAX_PATH_LENGTH, "/sys/fs/bpf/%s/xdp_flows_bandwidth", argv[1]);
    mapfd = bpf_obj_get(path);
    if(mapfd < 0) {
        printf("Could not get map file descriptor, exiting\n");
        fflush(stdout);
        return 1;
    }

    for(;;) {
        usleep(1000000);
        __uint128_t key = -1, prev_key = -1;
        while(bpf_map_get_next_key(mapfd, &prev_key, &key) == 0) {
            struct flow value;
            int error = bpf_map_lookup_elem(mapfd, &key, &value);
            if(error) {
                printf("Could not get value (%llu) from map, exiting\n", (unsigned long long) (key & 0xFFFFFFFFFFFFFFFF));
                fflush(stdout);
                return 1;
            }
            printf("data for flow (left 64 bits): %llu\ntime: %lu\nbytes: %lu\n\n", (unsigned long long) (key & 0xFFFFFFFFFFFFFFFF), value.time, value.bytes);
            prev_key = key;
        }
        printf("----------------------------------\n");
        fflush(stdout);
    }
}