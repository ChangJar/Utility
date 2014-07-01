/* enc.c
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

#define SALT_SIZE 8
#define DES3_BLOCK_SIZE 24

char* type;

/*
 * Makes a cyptographically secure key by stretMDMching a user entered key
 */
int GenerateKey(RNG* rng, byte* key, int size, byte* salt, int pad)
{
    int ret;

    ret = RNG_GenerateBlock(rng, salt, SALT_SIZE-1);
    if (ret != 0)
        return -1020;

    if (pad == 0)        /* sets first value of salt to check if the */
        salt[0] = 0;            /* message is padded */

    /* stretches key */
    ret = PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096, 
        size, SHA256);
    if (ret != 0)
        return -1030;

    return 0;
}

int Encrypt(char* name, byte* key, int size, char* in, char* out, byte* iv)
{
	Aes aes;
	Des3 des3;
	Camellia camellia;

	FILE*  inFile;
    FILE*  outFile;
	int block = GetAlgorithm(name);;

	RNG     rng;
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE] = {0};

    int     i = 0;
    int     ret = 0;
    int     inputLength;
    int     length;
    int     padCounter = 0;

	inFile = fopen(in, "r");
	outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    length = inputLength;
	/* pads the length until it evenly matches a block / increases pad number*/
    while (length % block != 0) {
        length++;
        padCounter++;
    }

    input = malloc(length);
    output = malloc(length);

    InitRng(&rng);

    /* reads from inFile and wrties whatever is there to the input array */
    ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (i = inputLength; i < length; i++) {
        /* padds the added characters with the number of pads */
        input[i] = padCounter;
    }

    ret = RNG_GenerateBlock(&rng, iv, block);
    if (ret != 0)
        return -1020;

    /* stretches key to fit size */
    ret = GenerateKey(&rng, key, size, salt, padCounter);
    if (ret != 0) 
        return -1040;

    /* sets key encrypts the message to ouput from input length + padding */
    if (strcmp(type, "aes") == 0) {
		ret = AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
	    if (ret != 0)
	        return -1001;
	    ret = AesCbcEncrypt(&aes, output, input, length);
	    if (ret != 0)
	        return -1005;
	}
	if (strcmp(type, "3des") == 0) {
		ret = Des3_SetKey(&des3, key, iv, DES_DECRYPTION);
	    if (ret != 0)
	        return -1002;
	    ret = Des3_CbcEncrypt(&des3, output, input, length);
	    if (ret != 0)
	        return -1005;
	}
	if (strcmp(type, "camellia") == 0){
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return -1001;
	    /* encrypts the message to the ouput based on input length + padding */
	    CamelliaCbcEncrypt(&camellia, output, input, length);
	}

    /* writes to outFile */
    fwrite(salt, 1, SALT_SIZE, outFile);
    fwrite(iv, 1, block, outFile);
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory*/
    memset(input, 0, length);
    memset(output, 0, length);
    memset(key, 0, size);
    memset(iv, 0 , block);
    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);
    return 0;
}

int GetAlgorithm(char* name)
{
	int ret;
	if (strncmp(name, "-aes", 4) == 0) {
		ret =  AES_BLOCK_SIZE;
		type = "aes";
	}
	else if (strncmp(name, "-3des", 5) == 0) {
		ret =  DES3_BLOCK_SIZE;
		type = "3des";
	}
	else if (strncmp(name, "-camellia", 6) == 0) {
		ret =  CAMELLIA_BLOCK_SIZE;
		type = "camellia";
	}
	else {
		ret =  -1;
	}
	return ret;
}