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

#include "util.h"

#define SALT_SIZE 8
#define DES3_BLOCK_SIZE 24

int GetAlgorithm(char* name, char** alg, char** mode, int* size)
{
	int 	ret = 0;
	char*	sz = 0;

	*alg = strtok(name, "-");
	*mode = strtok(NULL, "-");
	sz = strtok(NULL, "-");
	*size = atoi(sz);
	if (strcmp(*alg, "aes") == 0) {
		ret = AES_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            /* if the entered size does not match acceptable size */
            printf("Invalid AES key size\n");
            ret = -1;
        }
	}
	else if (strcmp(*alg, "3des") == 0) {
		ret = DES3_BLOCK_SIZE;
        if (*size != 56 && *size != 112 && *size != 168) {
            /* if the entered size does not match acceptable size */
            printf("Invalid 3DES key size\n");
            ret = -1;
        }
	}
	else if (strcmp(*alg, "camellia") == 0) {
	    ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            /* if the entered size does not match acceptable size */
            printf("Invalid Camellia key size\n");
            ret = -1;
        }
	}
	else {
		printf("Invalid algorithm: %s\n", *alg);
		ret = -1;
	}
    if (strcmp(*mode, "cbc") != 0) {
        printf("CBC is currently the only supported encryption mode\n");
        printf("Others to be implemented later.\n");
        ret = -1;
    }
	return ret;
}
/*
 * Makes a cyptographically secure key by stretching a user entered key
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

void Append(char* s, char c)
{
    int len = strlen(s);
    s[len] = c;
    s[len+1] = '\0';
}

int Encrypt(char* alg, char* mode, byte* key, int size, char* in, char* out, 
	byte* iv, int block)
{
	Aes aes;
	Des3 des3;
	Camellia camellia;

	FILE*  inFile;
    FILE*  outFile;

	RNG     rng;
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE] = {0};

    int     i = 0;
    int     ret = 0;
    int     inputLength;
    int     length;
    int     padCounter = 0;
    int 	fileCheck = 0;

	inFile = fopen(in, "r");
	if (inFile != NULL) {
		/* if there is a file. find lenght */
		fileCheck = 1;
	    fseek(inFile, 0, SEEK_END);
	    inputLength = ftell(inFile);
	    fseek(inFile, 0, SEEK_SET);
	    length = inputLength;
		/* pads the length until it matches a block / increases pad number */
	    while (length % block != 0) {
	        length++;
	        padCounter++;
	    }

	    input = malloc(length);
	    /* reads from inFile and wrties whatever is there to the input array */
	    ret = fread(input, 1, inputLength, inFile);
	}
	else {
		/* else use user entered data to encrypt */
		inputLength = sizeof(in);
		length = inputLength;
		/* pads the length until it matches a block / increases pad number */
	    while (length % block != 0) {
	        length++;
	        padCounter++;
	    }
    	input = malloc(length);
    	/* writes the entered text to the input buffer */
		memcpy(input, in, inputLength);
	}

	outFile = fopen(out, "w");    
    output = malloc(length);

    InitRng(&rng);

    for (i = inputLength; i < length; i++) {
        /* padds the added characters with the number of pads */
        input[i] = padCounter;
    }

    if (iv && iv[0] == '\0') {
    	ret = RNG_GenerateBlock(&rng, iv, block);
    	if (ret != 0)
        	return -1020;
	}
    /* stretches key to fit size */
    ret = GenerateKey(&rng, key, size, salt, padCounter);
    if (ret != 0) 
        return -1040;

    /* sets key encrypts the message to ouput from input length + padding */
    if (strcmp(alg, "aes") == 0) {
		ret = AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
	    if (ret != 0)
	        return -1001;
	    ret = AesCbcEncrypt(&aes, output, input, length);
	    if (ret != 0)
	        return -1005;
	}
	if (strcmp(alg, "3des") == 0) {
		ret = Des3_SetKey(&des3, key, iv, DES_ENCRYPTION);
	    if (ret != 0)
	        return -1002;
	    ret = Des3_CbcEncrypt(&des3, output, input, length);
	    if (ret != 0)
	        return -1005;
	}
	if (strcmp(alg, "camellia") == 0) {
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return -1001;
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
    memset(alg, 0, size);
    memset(mode, 0 , block);
    free(input);
    free(output);
    if(fileCheck == 1)
    	fclose(inFile);
    fclose(outFile);
    return 0;
}
int Decrypt(char* alg, char* mode, byte* key, int size, char* in, char* out, 
	byte* iv, int block)
{
	Aes aes;
	Des3 des3;
	Camellia camellia;

	FILE*  inFile;
    FILE*  outFile;

	RNG     rng;
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE] = {0};

    int     i = 0;
    int     ret = 0;
    int     length;
    int 	aSize = 0;

    inFile = fopen(in, "r");
	if (inFile == NULL) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    aSize = length;

    input = malloc(aSize);
    output = malloc(aSize);

    InitRng(&rng);

    /* reads from inFile and wrties whatever is there to the input array */
    ret = fread(input, 1, length, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (i = 0; i < SALT_SIZE; i++) {
        /* finds salt from input message */
        salt[i] = input[i];
    }
    if (iv  && iv[0] == '\0') {
	    for (i = SALT_SIZE; i < block + SALT_SIZE; i++) {
	        /* finds iv from input message */
	        iv[i - SALT_SIZE] = input[i];
	    }
	}

    /* replicates old key if keys match */
    ret = PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096, 
        size, SHA256);
    if (ret != 0)
        return -1050;

	/* change length to remove salt/iv block from being decrypted */
    length -= (block + SALT_SIZE);
    for (i = 0; i < length; i++) {
        /* shifts message: ignores salt/iv on message*/
        input[i] = input[i + (block + SALT_SIZE)];
    }
    /* sets key decrypts the message to ouput from input length */
    if (strcmp(alg, "aes") == 0) {
		ret = AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
	    if (ret != 0)
	        return -1001;
	    ret = AesCbcDecrypt(&aes, output, input, length);
	    if (ret != 0)
	        return -1005;
	}
	if (strcmp(alg, "3des") == 0) {
		ret = Des3_SetKey(&des3, key, iv, DES_DECRYPTION);
	    if (ret != 0)
	        return -1002;
	    ret = Des3_CbcDecrypt(&des3, output, input, length);
	    if (ret != 0)
	        return -1005;
	}
	if (strcmp(alg, "camellia") == 0) {
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return -1001;
	    /* encrypts the message to the ouput based on input length + padding */
	    CamelliaCbcDecrypt(&camellia, output, input, length);
	}

    if (salt[0] != 0) {
        /* reduces length based on number of padded elements  */
        length -= output[length-1];
    }
    /* writes output to the outFile based on shortened length */
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory*/
    memset(input, 0, aSize);
    memset(output, 0, aSize);
    memset(key, 0, size);
    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return 0;
}
