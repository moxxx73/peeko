#include <stdio.h>
#include <string.h> /* memcpy(), strchr() */
#include <stdlib.h> /* malloc(), free() */

#include "include/cafebabe.h"

#define MAX_THREADS 5

void usage(char *bn){
    printf("Usage: %s [options] address/name\n", bn);
    printf("Use \'-h\' if u dont know what to do\n");
    return;
}

void help(void){
    printf("\n");
    return;
}

int main(int argc, char *argv[]){
    char target[255];
    char *arg, *tmp1, *tmp2;
    int i=1, threads=MAX_THREADS, verbose=0;
    int porta, portb, x;
    if(argc < 2){
        usage(argv[0]);
        return 0;
    }
    for(;i<(argc-1);i++){
        if(argv[i][0] == '-'){
            switch(argv[i][1]){
                case 'h':
                  help();
                  return 0;
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
    }
    memcpy(target, argv[argc-1], 255);
    if(target[0] == '-') return 0;
    dedscan_main(target, porta, portb, threads, verbose);
    return 0;
}
