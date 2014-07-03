/* encrypt.c
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
    char*   name;
    char*   alg;
    char*   mode;
    char*   in;
    char*   out;
    byte*   key;
    byte*   iv;

    char    outName[256] = "encrypted";
    int     size = 0;
    int     i = 0;
    int     ret = 0;
    int     block = 0;
    int     keyCheck = 0;
    int     outCheck = 0;
    int     inCheck = 0;
    int     mark = 0;

    name = argv[1];
    block = GetAlgorithm(name, &alg, &mode, &size);

    if (block != -1) {
        key = malloc(size);        /* saves memory for entered keysize */
        iv = malloc(block);        /* saves memory for block size */
        memset(iv, 0, block);      /* sets all iv memory to 0 */
        
        argc-=2;
        argv+=2;

        while (argc > 0) {          /* reads all arguments in command line */
            if (strcmp(*argv, "-i") == 0) {
                inCheck = 1;
                in = *(++argv);
                argc--;
            }

            else if (strcmp(*argv, "-o") == 0) {
                if (argc != 1 && strcmp(*(argv+1), "-i") != 0 && strcmp(
                    *(argv+1), "-k") != 0 && strcmp(*(argv+1), "-iv") != 0) {
                    outCheck = 1;
                    out = *(++argv);
                    argc--;
                }
            }

            else if (strcmp(*argv, "-k") == 0) {
                if (argc != 1 && strcmp(*(argv+1), "-i") != 0 && strcmp(
                    *(argv+1), "-o") != 0 && strcmp(*(argv+1), "-iv") != 0) {
                    keyCheck = 1;
                    memcpy(key, *(++argv), size);
                    argc--;
                }
            }

            else if (strcmp(*argv, "-iv") == 0) {
                memcpy(iv, *(++argv), block);
                argc--;
                if (strlen((const char*)iv) != block) {
                    printf("Invalid IV. Must match algoritm block size.\n");
                    printf("Randomly Generating IV.\n");
                    memset(iv, 0, block);
                }
            }

            else {
                printf("invalid argument %s\n", *argv);
                break;
            }
            argc--;
            argv++;   
        }
    }
    else {
        return -1;
    }
    if (keyCheck != 1) {
        ret = NoEcho((char*)key, size);
    }
    if (inCheck == 1 && outCheck == 0) {
        out = outName;
        for (i = 0; i < strlen(in); i++) {
            if ((in[i] == '.') || (mark == 1)) {
                mark = 1;
                Append(out, in[i]);
            }
        }
        ret = Encrypt(alg, mode, key, size, in, out, iv, block);
    }
    else {
        printf("Must have input as either a file or standard I/O\n");
    }

    free(key);
    free(iv);
    return ret;
}
