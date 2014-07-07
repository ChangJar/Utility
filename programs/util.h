/* util.h
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

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <cyassl/options.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/des3.h>

#ifndef NO_SHA
    #include <cyassl/ctaocrypt/sha.h>
#endif

#ifndef NO_SHA256
    #include <cyassl/ctaocrypt/sha256.h>
#endif

#ifdef CYASSL_SHA512
    #include <cyassl/ctaocrypt/sha512.h>
#endif

#ifdef HAVE_BLAKE2
    #include <cyassl/ctaocrypt/blake2.h>
#endif

#ifdef HAVE_CAMELLIA
    #include <cyassl/ctaocrypt/camellia.h>
#endif

#ifndef UTIL_H_INCLUDED
	#define UTIL_H_INCLUDED

int GetAlgorithm(char* name, char** alg, char** mode, int* size);
int GenerateKey(RNG* rng, byte* key, int size, byte* salt, int pad);
int NoEcho(char* key, int size);
void Append(char* s, char c);
int Encrypt(char* alg, char* mode, byte* key, int size, char* in, 
	char* out, byte* iv, int block);
int Decrypt(char* alg, char* mode, byte* key, int size, char* in, 
	char* out, byte* iv, int block);
	
#ifndef NO_MD5
    int Md5Hash(char* in, char* out);
#endif

#ifndef NO_SHA
	int ShaHash(char* in, char* out);
#endif

#ifndef NO_SHA256
	int Sha256Hash(char* in, char* out);
#endif

#ifdef CYASSL_SHA384
	int Sha384Hash(char* in, char* out);
#endif

#ifdef CYASSL_SHA512
	int Sha512Hash(char* in, char* out);
#endif

#ifdef HAVE_BLAKE2
	int Blake2bHash(char* in, char* out);
#endif

#endif
