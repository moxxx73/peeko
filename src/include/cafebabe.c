#include "cafebabe.h"

extern char verbose;
extern char debug;
extern char paralell;

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
    int r=0, jpt=0, rm=0;
    char src[INET_ADDRSTRLEN];
    scan_a *bruh;
    if(args->porta <= 0){
        return 1;
    }
    r = resolve_name(name, args->addr);
    if(r != 0){
        return 1;
    }
    printf("[+] Target: %s (%s)\n", name, args->addr);
    if(getifaddr(args->ifn, src) < 0){
        printf("[!] Failed to fetch interface address\n");
        return 1;
    }
    printf("[+] Operating on interface: %s (%s)\n", args->ifn, src);
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
    bruh->id = 0xcc73;
    if(args->portb != 0){
        r = args->portb-args->porta;
        if(r < 0) return 1;
        jpt = r/t;
        rm = r%t;
        if(verbose) printf("\t[+] Running %d threads with %d jobs/thread\n", t, jpt);
        if(verbose && rm) printf("\t[+] %d jobs given to last thread\n", rm);
        if(debug || verbose){
            printf("\t[+] Disabling verbose/debug output\n");
            verbose = 0;
            debug = 0;
        }
        init_threads(bruh, args->portb, t, jpt, rm);
    }else{
        single_port(bruh);
    }
    free(bruh);
    return 0;
}
