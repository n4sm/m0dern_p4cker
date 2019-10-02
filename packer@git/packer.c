/* 
 * This file is part of the nasm distribution (https://github.com/n4sm/m0dern_p4cker/).
 * Copyright (c) 2019 nasm.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

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

	else if (argc == 3 && !strcmp(argv[2], "-h"))
	{
		printf("Help : \n");
		printf("\t\t%s <target_file> xor : target_file is encrypted (only xor encryption) with a random key \n", argv[0]);
		printf("\t\t%s <target_file> not : target_file is encrypted (xor and not encryption) with a random key \n", argv[0]);
		printf("\t\t%s <target_file> xorp : target_file is encrypted (complex encryption) with a random key \n", argv[0]);
	}
	
	
	else if (argc != 2)
	{
		printf("Usage : <%s> <elf_target> <stub>\n", argv[0]);
	}

	return 0;
}


