#include "../include/results.h"

results_d *init_results(void){
    results_d *ret;
    ret = (results_d *)malloc(RESULTS_SIZ);
    if(ret){
        ret->ip_string = NULL;
        ret->open_ports = NULL;
        ret->number_of_open = 0;
        ret->packets_recvd = 0;
        return ret;
    }
    return NULL;
}

int add_open_port(results_d *results, short port){
    short amount;
    if(!results){
        return -1;
    }
    amount = results->number_of_open;
    amount += 1;
    results->open_ports = (short *)realloc(results->open_ports, (amount*2));
    if(!results->open_ports) return -1;
    results->open_ports[(amount-1)] = port;
    results->number_of_open = amount;
    return 0;
}


void display_results(results_d *results){
    int x=0;
    if(results->number_of_open){
        for(;x<results->number_of_open;x++){
            printf("[%s%s%s] Port %hu is open\n", GREENC, results->ip_string, RESET, results->open_ports[x]);
        }
    }
    return;
}
