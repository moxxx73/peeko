#include <unistd.h> /* close() */
#include <stdio.h>

#include "bpf.h"

/* Just probes a single port */
int single_port(char *, char *, int, int, int);
