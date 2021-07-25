#include "cafebabe.h"

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

int cafebabe_main(cafebabe *args, char *name, int t){
    int r, jpt, rm;
    if(args->porta <= 0){
        return 1;
    }
    r = resolve_name(name, args->addr);
    if(r != 0){
        return 1;
    }
    if(args->verbose == 1) printf("[+] Target: %s (%s)\n", name, args->addr);
    if(args->portb != 0){
        r = args->portb-args->porta;
        if(r < 0) return 1;
        jpt = r/t;
        rm = r%t;
        //init_threads();
    }
    single_port(args->ifn, args->addr, args->porta, args->portc, args->verbose);
    return 0;
}
