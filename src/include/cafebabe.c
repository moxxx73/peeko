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

int getifaddr(char *ifn, char *b){
    struct ifreq ifr;
    int s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return -1;
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, ifn, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        return -1;
    }
    close(s);
    if(inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, b, INET_ADDRSTRLEN) == NULL){
        return -1;
    }
    return 0;
}

int cafebabe_main(cafebabe *args, char *name, int t){
    int r, jpt, rm;
    char src[INET_ADDRSTRLEN];
    scan_a *bruh;
    if(args->porta <= 0){
        return 1;
    }
    r = resolve_name(name, args->addr);
    if(r != 0){
        return 1;
    }
    if(args->verbose == 1) printf("[+] Target: %s (%s)\n", name, args->addr);
    if(getifaddr(args->ifn, src) < 0){
        printf("[!] Failed to fetch interface address\n");
        return 1;
    }
    if(args->verbose==1) printf("[+] Interface: %s (%s)\n", args->ifn, src);
    bruh = (scan_a *)malloc(sizeof(scan_a));
    if(bruh == NULL){
        printf("[!] Failed to initialise scan_a structure\n");
        return 1;
    }
    inet_pton(AF_INET, args->addr, &bruh->dst);
    inet_pton(AF_INET, src, &bruh->src);
    bruh->ifn = args->ifn;
    bruh->sport = args->portc;
    bruh->daport = args->porta;
    bruh->dbport = args->portb;
    bruh->verbose = args->verbose;
    bruh->id = 0xcc73;
    if(args->portb != 0){
        r = args->portb-args->porta;
        if(r < 0) return 1;
        jpt = r/t;
        rm = r%t;
        //init_threads();
    }else{
        single_port(bruh);
    }
    free(bruh);
    return 0;
}
