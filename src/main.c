#include <stdio.h>
#include <unistd.h> /* getuid() */
#include <string.h> /* memcpy(), strchr() */
#include <stdlib.h> /* malloc(), free() */

#include "include/cafebabe.h"

#define MAX_THREADS 5
#define PORTC 666
#define IFNAMSIZ 16

void usage(char *bn){
    printf("Usage: %s [options] address/name\n", bn);
    return;
}

void help(void){
    printf("### Options ###\n");
    printf("\t-v: Enable verbose output\n");
    printf("\t-p: Specify which port(s) to scan. example: -p 80, 80-100\n");
    printf("\t-t: Number of threads to run\n");
    return;
}

int main(int argc, char *argv[]){
    char target[255];
    char ifn[] = "en0\0";
    char *arg, *tmp1, *tmp2;
    int i=1, threads=MAX_THREADS, verbose=0;
    int porta=0, portb=0, x=0;
    cafebabe *args;
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
    if(getuid() != 0){
        printf("This build requires that it be ran as root\n");
        return 1;
    }
    args->ifn = (char *)malloc(IFNAMSIZ);
    args->addr = (char *)malloc(INET_ADDRSTRLEN);
    for(;i<(argc-1);i++){
        if(argv[i][0] == '-'){
            switch(argv[i][1]){
                case 'p':
                  if((i+1) != argc){
                      arg = argv[i+1];
                      tmp1 = strchr(arg, '-');
                      if(tmp1 == NULL){
                          porta = atoi(arg);
                      }else{
                          x = tmp1-arg;
                          tmp1=NULL;
                          tmp1 = (char *)malloc(x+1);
                          tmp2 = (char *)malloc(strlen(arg)-x);
                          memcpy(tmp1, arg, x);
                          memcpy(tmp2, (arg+x+1), (strlen(arg)-x));
                          porta = atoi(tmp1);
                          portb = atoi(tmp2);
                          free(tmp1);
                          free(tmp2);
                      }
                  }
                case 't':
                  if((i+1) != argc){
                      arg = argv[i+1];
                      threads = atoi(arg);
                  }
                case 'v':
                  verbose=1;
            }
        }
        else{
            if(argv[i-1][0] != '-'){
                memset(target, 0, 255);
                memcpy(target, argv[i], 255);
            }
        }
    }
    memcpy(args->ifn, ifn, IFNAMSIZ);
    args->porta = porta;
    args->portb = portb;
    args->portc = PORTC;
    args->verbose = verbose;
    if(target[0] == '-') return 0;
    cafebabe_main(args, target, threads);
    return 0;
}
