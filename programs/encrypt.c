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

#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <cyassl/options.h>
#include <cyassl/ctaocrypt/sha256.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/pwdbased.h>

int main(int argc, char** argv)
{
    const   char* in;
    const   char* out;
    byte*   key;
    byte*   iv;

    argc--;
    argv++;
    while (argc > 0) {
        if (strcmp(*argv, "-i") == 0) {
            in = *(++argv);
            argc--;
printf("%s\n", in);
        }
        else if (strcmp(*argv, "-o") == 0) {
            out = *(++argv);
            argc--;
printf("%s\n", out);
        }
        else if (strcmp(*argv, "-k") == 0) {
            key = *(++argv);
            argc--;
printf("%s\n", key);
        }
        else if (strcmp(*argv, "-iv") == 0) {
            iv = *(++argv);
            argc--;
printf("%s\n", iv);
        }
        else {
            printf("invalid argument %s\n", *argv);
            break;
        }
        argc--;
        argv++;
    }
    return 0;
}

/******************************NEED HEADERFILE THAT INCLUDES ALL CRYPTO OPTIONS***************************************/
