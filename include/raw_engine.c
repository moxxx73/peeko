#include "raw_engine.h"

/* just a wrapper function for now... */
int *open_descriptor(char *ifn){
    int *r;
    r = (int *)malloc(sizeof(int)*2);
    if(r == NULL) return NULL;
    r[0] = openDev();
    if(r[0] < 0){
        free(r);
        return NULL;
    }
    r[1] = setAll(r[0], ifn);
    if(r[1] < 0){
        free(r);
        return NULL;
    }
    return r;
}

/* again, another wrapper function... */
int set_filter(int fd, filter_data *d){
    int r;
    r = setFilter(fd, d);
    return r;
}

int read_descriptor(int fd, int blen){
    struct bpfData *data;
    int bytes = 0;
    data = initList();
    if(data == NULL) return -1;
    bytes = readDev(fd, data, blen);
    trashAll(data);
    return bytes;
}
