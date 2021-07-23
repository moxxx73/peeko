#include "dedscan.h"

int resolve_name(char *name, char *b){
    struct hostent *r;
    r = gethostbyname(name);
    if(r != NULL){
        if(inet_ntop(AF_INET, ((struct sockaddr_in *)r->h_addr_list[0]), b, INET_ADDRSTRLEN) != NULL){
            return 0;
        }
    }
    return -1;
}

int cafebabe_main(char *target, int porta, int portb, int t, int verbose){
    char addr[INET_ADDRSTRLEN];
    int r;
    if(porta <= 0){
        return 1;
    }
    r = resolve_name(target, addr);
    if(r != 0){
        return 1;
    }
        
    return 0;
}
