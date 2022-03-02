#include <stdio.h>
#include <unistd.h> /* getuid() */
#include <string.h> /* memcpy(), strchr() */
#include <stdlib.h> /* malloc(), free() */

#include "../include/cafebabe.h"

#define MAX_THREADS 5
#define SPORT 666

#define NAME "cafebabe"
#define VERSION "1.42"
#define COMMON_PATH "/opt/cafebabe/common-cafebabe"
#define IFN_NAME "wlan0\0"

char verbose=0;

void usage(char *bn){
    printf("Usage: %s%s%s [options] -d address/hostname\n", GREENC, bn, RESET);
    return;
}

void help(void){
    printf("### Options ###\n");
    printf("  -v: Enable verbose output\n");
    printf("  -p: Specify which port(s) to scan. example: -p 80, -p 80-100, -p 21,22,80 \n");
    printf("  -T: Number of threads to run\n");
    printf("  -t: set timeout (seconds). Default is 5 seconds\n");
    printf("  -i: specify which interface use (priviliged scans only)\n");
    printf("  -q: don\'t display name and ascii\n");
    printf("\n### Scan Method ###\n");
    printf("  -sS: TCP SYN\n");
    printf("  -sC: TCP Connect()\n");
    printf("\n");
    return;
}

int main(int argc, char *argv[]){
    char target[255];
    char ifn[16];
    char resolve_target=1;
    int threads=MAX_THREADS;
    char quiet=0;
    char *arg, method=HANDSHAKE_SCAN;
    int i=1;
    cafebabe *args=NULL;
    parse_r *list=NULL;
    if(argc < 2){
        usage(argv[0]);
        help();
        return 0;
    }
    memcpy(ifn, IFN_NAME, 16);
    args = (cafebabe *)malloc(sizeof(cafebabe));
    if(args == NULL){
        printf("[!] failed to allocate memory for cafebabe structure\n");
        return 1;
    }
    args->ifn = (char *)malloc(IF_NAMESIZE);
    args->addr = (char *)malloc(INET_ADDRSTRLEN);
    args->timeout = 5;
    for(;i<(argc);i++){
        if(argv[i][0] == '-'){
            switch(argv[i][1]){
                case 'p':
                    if((i+1) >= argc) return 1;
                    if((list = parse_port_args(argv[i+1])) == NULL) return 1;
                    break;
                case 'T':
                    if((i+1) >= argc) return 1;
                    arg = argv[i+1];
                    threads = atoi(arg);
                    break;
                case 'v':
                    verbose=1;
                    break;
                case 't':
                    if((i+1) >= argc) return 1;
                    args->timeout = atoi(argv[i+1]);
                    break;
                case 'q':
                  quiet = 1;
                  break;
                case 'n':
                    resolve_target = 0;
                    break;
                case 's':
                    if(strlen(argv[i]) > 2){
                        method ^= method;
                        switch(argv[i][2]){
                            case 'S':
                                method = method^SYN_SCAN;
                                break;
                            case 'C':
                                method = method^HANDSHAKE_SCAN;
                                break;
                        }
                    }else{
                        printf("Scan method was not provided\n");
                        return 1;
                    }
                    break;
                case 'i':
                    if((i+1) >= argc) return 1;
                    strncpy(ifn, argv[i+1], IF_NAMESIZE);
                    break;
                case 'd':
                    if((i+1) >= argc) return 1;
                    memset(target, 0, 255);
                    memcpy(target, argv[i+1], 255);
                    break;
            }
        }
    }
    if(!list){
        list = parse_file(COMMON_PATH);
        if(!list) return 1;
    }
    if(!quiet){
      printf("(\\(\\\n");
      printf("(-.-)  %s Version: %s\n", NAME, VERSION);
      printf("c(\")(\")\n");
      printf("%s==============================%s\n", GREENC, RESET);
    }
    /* check whether the user running the code has the necessary */
    /* privileges to use a raw scan method */
    if(!(method&HANDSHAKE_SCAN) && getuid() > 0){
        printf("[%sERROR%s] The selected scan method requires you run this binary as root\n", REDC, RESET);
        free(args->ifn);
        free(args->addr);
        free(args);
        return 0;
    }
    memcpy(args->ifn, ifn, IF_NAMESIZE);
    args->sport = (short)SPORT;
    args->method = method;
    cafebabe_main(args, target, list, threads, resolve_target);
    return 0;
}
