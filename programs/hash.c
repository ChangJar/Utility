/* hash.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "util.h"
 
int main(int argc, char** argv)
{
	int ret = 0;
	int i = 0;
    char*   in = 0;
    char*   out = 0;
	char* algs[] = {"-md5","-sha","-sha256","-sha384","-sha512","-blake2b"};
	char* alg;
	int num = -1;
	int inCheck = 0;
	int outCheck = 0;

	if (argc < 2) {
        printf("Usage: cyassl hash <-algorithm> <-i filename> [-o filename]\n");
        return -1;
    }
    
    for (i = 0; i < 6; i++) {
		if (strcmp(argv[1], algs[i]) == 0) {
			alg = argv[1];
			num = i;
		}
	}
	if (num < 0) {
		printf("Invalid algorithm\n");
		return -1;
	}
	argc-=2;
    argv+=2;

	while (argc > 0) {          /* reads all arguments in command line */
	    if (strcmp(*argv, "-i") == 0) {
	    	inCheck = 1;
	        in = *(++argv);
	        argc--;
	    }

	    else if (strcmp(*argv, "-o") == 0) {
        	outCheck = 1;
            out = *(++argv);
            argc--;
	    }
	    argc--;
	}
    if (inCheck == 1 && outCheck == 0) {
    	out = malloc(strlen(in) + 1 + strlen(alg));
        alg = strtok(alg, "-");
        strcpy(out, in);
        strcat(out, ".");
        strcat(out, alg);
    }
    else if (inCheck == 0) {
        printf("Must have input as either a file or standard I/O\n");
        return -1;
    }
	switch(num) {
#ifndef NO_MD5
        case 0:
        Md5Hash(in, out);
            break;
#endif

#ifndef NO_SHA
        case 1:
        ShaHash(in, out);
            break;
#endif

#ifndef NO_SHA256
        case 2:
        Sha256Hash(in, out);
            break;
#endif

#ifdef CYASSL_SHA384
        case 3:
        Sha384Hash(in, out);
            break;
#endif

#ifdef CYASSL_SHA512
        case 4:
        Sha512Hash(in, out);
            break;
#endif

#ifdef HAVE_BLAKE2
        case 5:
        Blake2bHash(in, out);
            break;
#endif
        default :
        printf("Invalid algorithm selection.\n");
        printf("Are you sure this option has been configured?\n");
    }

    if (outCheck == 0)
    	free(out);

	return ret;
}
