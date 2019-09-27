#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <gelf.h>
#include <stdarg.h>
#include <getopt.h>
#include <ctype.h>
#include <capstone/capstone.h>
#include <time.h> 

#include "include.h"


int main(int argc, char **argv){

	if (argc == 3 && !strcmp(argv[2], "xor"))
	{
		xor_encrypt(argv[1]);
	}

	else if (argc == 3 && !strcmp(argv[2], "not"))
	{
		not_encrypt(argv[1]);
	}

	else if (argc == 3 && !strcmp(argv[2], "xorp"))
	{
		complexe_encrypt(argv[1]);
	}
	
	else if (argc != 2)
	{
		printf("Usage : <%s> <elf_target> <stub>\n", argv[0]);
	}

	return 0;
}


