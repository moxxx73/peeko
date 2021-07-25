#include "scan.h"

int single_port(char *ifn, char *t, int dport, int sport, int v){
    int s, r;
    s = openDev();
    if(s < 0) return 1;
    r = setAll(s, ifn);
    if(r > 0){
        if(v == 1) printf("[+] Opened /dev/bpf (Buffer: %d)\n", r);
    }
    close(s);
    return 0;
}
