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

#include "enc.h"

int NoEcho(char* key, int size)
{
    struct termios oflags, nflags;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        printf("Error\n");
        return -1060;
    }

    printf("Key: ");
    fgets(key, size, stdin);
    key[strlen(key) - 1] = 0;

    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        printf("Error\n");
        return -1070;
    }
    return 0;
}

int main(int argc, char** argv)
{
    char*   name = '\0';
    char*   in = '\0';
    char*   out = '\0';
    byte*   key = '\0';
    byte*   iv = '\0';
    char    sz[3] = {1};
    int     size = 0;
    int     i = 0;
    int     j = 0;
    int     ret = 0;
    int     block = 0;

    name = argv[1];
    block = GetAlgorithm(name);

    if (block != -1) {
        i = strlen(name)-3;
        while(i <= strlen(name)) { /* sets the last characters of name to sz */
            sz[j] = name[i];
            i++;
            j++;
        } 
        size = atoi(sz);           /* sets size from the numbers of sz */
        key = malloc(size);        /* saves memory for entered keysize */
        iv = malloc(block);        /* saves memory for block size */
        memset(iv, 0, block);      /* sets all iv memory to 0 */
        if (size == 0) {
            printf("Invalid Size.\n");
            return -1;
        } 
        argc-=2;
        argv+=2;

        while (argc > 0) {          /* reads all arguments in command line */
            if (strcmp(*argv, "-i") == 0) {
                in = *(++argv);
                argc--;
            }

            else if (strcmp(*argv, "-o") == 0) {
                out = *(++argv);
                argc--;
            }

            else if (strcmp(*argv, "-k") == 0) {

                if (argc != 1 && strcmp(*(argv+1), "-i") != 0 && strcmp(
                    *(argv+1), "-o") != 0 && strcmp(*(argv+1), "-iv") != 0) {
                    memcpy(key, *(++argv), size);
                    argc--;
                }
                else {
                    ret = NoEcho((char*)key, size);
                }
            }

            else if (strcmp(*argv, "-iv") == 0) {
                memcpy(iv, *(++argv), block);
                argc--;
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
        printf("Invalid Algorithm Name: %s\n", name);
        return -1;
    }
    ret = Encrypt(name, key, size, in, out, iv);

    free(key);
    free(iv);
    return ret;
}
