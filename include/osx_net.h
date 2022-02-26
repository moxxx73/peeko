#include "bpf.h"

struct bpfData *read_dev(int, int);

void port_state_bpf(struct bpfData *, int);
