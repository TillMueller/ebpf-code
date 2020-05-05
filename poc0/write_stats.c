#include <stdio.h>
#include <unistd.h>
#include <bpf.h>
#include <libbpf.h>

#define MAX_PATH_LENGTH 4096
#define NUMBER_OF_INTERVALS 10

int main(int argc, char* argv[]) {
    int mapfd;
    char path[MAX_PATH_LENGTH];
    snprintf(path, MAX_PATH_LENGTH, "/sys/fs/bpf/%s/xdp_stats_map", argv[1]);
    mapfd = bpf_obj_get(path);
    if(mapfd < 0) {
        printf("Could not get map file descriptor, exiting\n");
        fflush(stdout);
        return 1;
    }

    int intervals[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 256};
    long long unsigned int data[NUMBER_OF_INTERVALS] = { 0 };

    for(;;) {
        usleep(1000000);
        int interval = 0;
        for(int i = 0; i < 256; i++) {
            if(intervals[interval] <= i) {
                interval++;
                if(interval > NUMBER_OF_INTERVALS - 1) {
                    printf("interval too large: %d, exiting\n", interval);
                    fflush(stdout);
                    return 1;
                }
            }
            long long unsigned int value;
            int key = i;
            int error = bpf_map_lookup_elem(mapfd, &key, &value);
            if(error != 0) {
                printf("Could not get value (%d) from map, exiting\n", i);
                fflush(stdout);
                return 1;
            }
            data[interval] += value;
        }
        for(int i = 0; i < NUMBER_OF_INTERVALS - 1; i++)
            printf("interval (%03d - %03d]: %llu\n", intervals[i], intervals[i + 1], data[i + 1]);
        printf("\n");
        fflush(stdout);
    }
}