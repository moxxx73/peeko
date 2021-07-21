#include <stdio.h>

void usage(char *bn){
	printf("Usage: %s [options] address/name\n", bn);
	printf("Use \'-help\' if u dont know what to do\n");
	return;
}

void help(void){
	return
}

int main(int argc, char *argv[]){
	if(argc < 2) usage(argv[0]);
	return 0;
}
