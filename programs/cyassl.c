/* cyassl.c
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
    int i;
    int num = -1;
    char* commands[] = {"encrypt", "decrypt", "hash", "benchmark"};

    if (argc < 2) {
        printf("USAGE: cyassl COMMAND [options]... [arguments]...\n");
    }

    for (i = 0; i < 4; i++) {
        if (strcmp(argv[1], commands[i]) == 0) 
            num = i;
    }

    if (num == 0) { 
        Enc(argc, argv);
    }
    else if (num == 1) {
        Dec(argc, argv);
    }
    else if (num == 2) {
        Has(argc, argv);
    }
    else if (num == 3) {
        Bench(argc, argv);
    }
    else {
        printf("Invalid selection. For a list of commands type -help\n");
        return -1;
    }
    return ret;
}
