#include <stdio.h>
#include <unistd.h> 
#include <string.h>
#include <stdlib.h>

#include "../include/cafebabe.h"

/* considering changing some of the below        */
/* defenitions so they're just regular variables */
/* that are loaded in from a config file         */

#define MAX_THREADS 5
#define SPORT 666

#define NAME "cafebabe"
#define VERSION "1.44"
#define COMMON_PATH "$CHANGE/cafebabe/common-cafebabe"
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
    printf("  -t: set timeout (seconds). Default is 5 seconds\n");
    printf("  -i: specify which interface use (priviliged scans only)\n");
    printf("  -q: don\'t display name and ascii art\n");
    printf("\n### Scan Method ###\n");
    printf("  -sS: TCP SYN\n");
    printf("  -sC: TCP Connect()\n");
    printf("\n");
    return;
}

int main(int argc, char *argv[]){
    /* initialize variables as a precaution */
    /* dont want any junk slipping through  */
    char target[255];
    char ifn[16];
    char resolve_target=1;
    char quiet=0;
    char method=HANDSHAKE_SCAN;
    int i=1;
    cafebabe *args=NULL;
    parse_r *list=NULL;

    if(argc < 2){
        usage(argv[0]);
        printf("  use -h flag to for more detailed usage\n");
        return 0;
    }
    /* initialize ifn buffer   */
    /* removing any junk bytes */
    memset(ifn, 0x00, 16);
    memcpy(ifn, IFN_NAME, 16);

    /* cafebabe structure is defined in cafebabe/include/cafebabe.h */
    args = (cafebabe *)malloc(sizeof(cafebabe));
    if(args == NULL){
        err_msg("main():malloc()");
        return 1;
    }

    if(!(args->ifn = (char *)malloc(IF_NAMESIZE))){
        err_msg("main():malloc()");
        return 1;
    }
    if(!(args->addr = (char *)malloc(INET_ADDRSTRLEN))){
        err_msg("main():malloc()");
        return 1;
    }
    args->timeout = 5;

    /* parsing CLI args */
    for(;i<(argc);i++){
        if(argv[i][0] == '-'){
            switch(argv[i][1]){
                case 'h':
                    usage(argv[0]);
                    help();
                    return 0;
                case 'p':
                    if((i+1) >= argc) return 1;
                    if((list = parse_port_args(argv[i+1])) == NULL) return 1;
                    break;
                /* verbose output has been left behind       */
                /* in recent updates but i do plan to use it */
                case 'v':
                    verbose=1;
                    break;
                case 't':
                    if((i+1) >= argc) return 1;
                    args->timeout = atoi(argv[i+1]);
                    break;
                /* silences ascii art output */
                case 'q':
                  quiet = 1;
                  break;
                /* if the target supplied is an IP address  */
                /* then theres not much use in this feature */
                case 'n':
                    resolve_target = 0;
                    break;
                /* thought i'd be fancy and store the chosen */
                /* scan method using individual bits         */
                case 's':
                    if(strlen(argv[i]) > 2){
                        method ^= method;
                        switch(argv[i][2]){
                            case 'S':
                                /* set second bit to 1 */
                                method = method^SYN_SCAN;
                                break;
                            case 'C':
                                /* as its the default scan method */
                                /* no new bits are set to 1 or 0  */
                                method = method^HANDSHAKE_SCAN;
                                break;
                        }
                    }else return 1;
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
    /* if no port argument was provided                       */
    /* default to ports stored in COMMON_PATH/common-cafebabe */
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

    /* check whether the user running the binary has the necessary */
    /* privileges to use the selected scan method                  */
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
    cafebabe_main(args, target, list, resolve_target);
    return 0;
}
