#include <stdio.h>
#include <unistd.h> /* getuid() */
#include <string.h> /* memcpy(), strchr() */
#include <stdlib.h> /* malloc(), free() */

#include "../include/cafebabe.h"

#define MAX_THREADS 5
#define SPORT 666

#define NAME "Cafebabe"
#define VERSION "73-201021-b465"

#if __APPLE__
    #define IFN_NAME "en0\0"
#else
    #define IFN_NAME "wlp3s0\0"
#endif

char verbose=0;
char underline[] = "\033[4m";
char reset[] = "\033[0m";
char opt_arr[2][4] = {"CON", "SYN"};
char arr_len=2;

void usage(char *bn){
    printf("Usage: %s [options] address/hostname\n", bn);
    return;
}

void help(void){
    printf("### Options ###\n");
    printf("\t-v: Enable verbose output\n");
    printf("\t-p: Specify which port(s) to scan. example: -p 80, -p 80-100, -p 21,22,80 \n");
    printf("\t-T: Number of threads to run\n");
    printf("\t-m: choose a scan method from the options provided below:\n");
    printf("\t    SYN: TCP SYN scan\n");
    printf("\t    CON: TCP connect() scan\n");
    printf("\t-t: set timeout (seconds). Default is 5 seconds\n");
    return;
}

int main(int argc, char *argv[]){
    char target[255];
    /* static for now, i'll add the option to change it later */
    char ifn[16];
    char opt_buf[4];
    char *arg, method=SYN_METH;
    int x;
    int i=1, threads=MAX_THREADS;
    cafebabe *args;
    parse_r *list;
    memcpy(ifn, IFN_NAME, 16);
    if(argc < 2){
        usage(argv[0]);
        help();
        return 0;
    }
    args = (cafebabe *)malloc(sizeof(cafebabe));
    if(args == NULL){
        printf("[!] failed to allocate memory for cafebabe structure\n");
        return 1;
    }
    args->ifn = (char *)malloc(IFNAMSIZ);
    args->addr = (char *)malloc(INET_ADDRSTRLEN);
    args->timeout = 5;
    for(;i<(argc-1);i++){
        if(argv[i][0] == '-'){
            switch(argv[i][1]){
                case 'p':
                    if((i+1) != argc){
                        if((list = parse_port_args(argv[i+1])) == NULL) return -1;
                        break;
                    }
                case 'T':
                    if((i+1) != argc){
                        arg = argv[i+1];
                        threads = atoi(arg);
                    }
                    break;
                case 'v':
                    verbose=1;
                    break;
                case 't':
                    if((i+1) != argc){
                        args->timeout = atoi(argv[i+1]);
                    }
                    break;
                /*
                case 'd':
                    debug=1;
                    break;
                */
                case 'm':
                    if((i+1) != argc){
                        memcpy(opt_buf, argv[i+1], 3);
                        for(x=0;x<arr_len;x++){
                            if(strncmp(opt_buf, opt_arr[x], 3) == 0) method = (char)x;
                        }
                    }
            }
        }
    }
    printf("%s | Version: %s\n", NAME, VERSION);
    if(method > TCP_CON && getuid() != 0){
        printf("The scan method being used requires that u run this binary as root\n");
        printf("sorrryyy...\n");
        free(args->ifn);
        free(args->addr);
        free(args);
        return 0;
    }
    memset(target, 0, 255);
    memcpy(target, argv[argc-1], 255);
    memcpy(args->ifn, ifn, IFNAMSIZ);
    args->sport = (short)SPORT;
    args->method = method;
    cafebabe_main(args, target, list, threads);
    return 0;
}
