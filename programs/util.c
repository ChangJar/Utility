/* util.c
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

#ifdef HAVE_BLAKE2

#define BLAKE_DIGEST_SIZE 64

#endif /* HAVE_BLAKE2 */

int loop = 1;
int64_t blocks;

int Enc(int argc, char** argv)
{
    char*    name;
    char*    alg;
    char*    mode;
    char*    in;
    char*    out;
    byte*    key;
    byte*    iv;

    char     outName[256] = "encrypted";
    int      size = 0;
    int      i = 0;
    int      ret = 0;
    int      block = 0;
    int      keyCheck = 0;   
    int      inCheck = 0;
    int      outCheck = 0;
    int      mark = 0;

    for (i = 2; i < argc; i++) {
       if (strcmp(argv[i], "-help") == 0) {
            printf("\nUSAGE: cyassl encrypt <-algorithm> <-i filename> ");
            printf("[-o filename] [-k password] [-iv IV]\n\n"
                   "Acceptable Algorithms");
            printf("\n-aes-cbc-128\t\t-aes-cbc-192\t\t-aes-cbc-256\n");
            printf("-3des-cbc-56\t\t-3des-cbc-112\t\t-3des-cbc-168\n");
            printf("-camellia-cbc-128\t-camellia-cbc-192\t"
                   "-camellia-cbc-256\n\n");
            return 0;
        }
    }

    name = argv[2];
    block = GetAlgorithm(name, &alg, &mode, &size);
    if (block != -1) {
        key = malloc(size);
        iv = malloc(block);
        memset(iv, 0, block);

        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
                in = argv[i+1];
                inCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
                out = argv[i+1];
                outCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-k") == 0 && argv[i+1] != NULL) {
                memcpy(key, argv[i+1], size);
                keyCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-iv") == 0 && argv[i+1] != NULL) {
                if (strlen(argv[i+1]) != block) {
                    printf("Invalid IV. Must match algorithm block size.\n");
                    printf("Randomly Generating IV.\n");
                }
                else {
                    iv = memcpy(iv, argv[i+1], block);
                }
                i++;
            }
            else {
                printf("Unknown argument %s. Ignoring\n", argv[i]);
            }
        }
        if (inCheck == 0) {
            printf("Must have input as either a file or standard I/O\n");
            return -1;
        }
        if (keyCheck == 0) {
            ret = NoEcho((char*)key, size);
        }
        if (outCheck == 0) {
            out = outName;
            for (i = 0; i < strlen(in); i++) {
                if ((in[i] == '.') || (mark == 1)) {
                    mark = 1;
                    Append(out, in[i]);
                }
            }
        }
        ret = Encrypt(alg, mode, key, size, in, out, iv, block);

        free(key);
        free(iv);
    }
    return ret;
}

int Dec(int argc, char** argv)
{
    char*    name;
    char*    alg;
    char*    mode;
    char*    in;
    char*    out;
    byte*    key;
    byte*    iv;

    char     outName[256] = "decrypted";
    int      size = 0;
    int      i = 0;
    int      ret = 0;
    int      block = 0;
    int      keyCheck = 0;   
    int      inCheck = 0;
    int      outCheck = 0;
    int      mark = 0;

    for (i = 2; i < argc; i++) {
       if (strcmp(argv[i], "-help") == 0) {
            printf("\nUSAGE: cyassl decrypt <-algorithm> <-i filename> ");
            printf("[-o filename] [-k password] [-iv IV]\n\n"
                   "Acceptable Algorithms");
            printf("\n-aes-cbc-128\t\t-aes-cbc-192\t\t-aes-cbc-256\n");
            printf("-3des-cbc-56\t\t-3des-cbc-112\t\t-3des-cbc-168\n");
            printf("-camellia-cbc-128\t-camellia-cbc-192\t"
                   "-camellia-cbc-256\n\n");
            return 0;
        }
    }

    name = argv[2];
    block = GetAlgorithm(name, &alg, &mode, &size);
    if (block != -1) {
        key = malloc(size);
        iv = malloc(block);
        memset(iv, 0, block);

        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
                in = argv[i+1];
                inCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
                out = argv[i+1];
                outCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-k") == 0 && argv[i+1] != NULL) {
                memcpy(key, argv[i+1], size);
                keyCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-iv") == 0 && argv[i+1] != NULL) {
                if (strlen(argv[i+1]) != block) {
                    printf("Invalid IV. Must match algorithm block size.\n");
                    printf("Randomly Generating IV.\n");
                }
                else {
                    iv = memcpy(iv, argv[i+1], block);
                }
                i++;
            }
            else {
                printf("Unknown argument %s. Ignoring\n", argv[i]);
            }
        }
        if (inCheck == 0) {
            printf("Must have input as a file\n");
            return -1;
        }
        if (keyCheck == 0) {
            ret = NoEcho((char*)key, size);
        }
        if (outCheck == 0) {
            out = outName;
            for (i = 0; i < strlen(in); i++) {
                if ((in[i] == '.') || (mark == 1)) {
                    mark = 1;
                    Append(out, in[i]);
                }
            }
        }
        ret = Decrypt(alg, mode, key, size, in ,out, iv, block);

        free(key);
        free(iv);
    }
    return ret;
}

int Has(int argc, char** argv)
{
	int ret = 0;
	int i = 0;
    char*   in = 0;
    char*   out = 0;
	char* algs[] = {"-md5","-sha","-sha256","-sha384","-sha512","-blake2b"};
	char* alg;
	int num = -1;
    int size = 0;
	int inCheck = 0;
	int outCheck = 0;

	for (i = 2; i < argc; i++) {
       if (strcmp(argv[i], "-help") == 0) {
            printf("\nUSAGE: cyassl hash <-algorithm> <-i filename>"
                   " [-o filename]");
            printf(" [-s size](*size use for Blake2b only between 0-64*)\n");
            printf("\nAcceptable Algorithms\n");
            for (i = 0; i < 6; i++) {
                printf("%s\n", algs[i]);
            }
            printf("\n");
            return 0;
        }
    } 
    for (i = 0; i < 6; i++) {
		if (strcmp(argv[2], algs[i]) == 0) {
			alg = argv[2];
			num = i;
		}
	}
	if (num < 0) {
		printf("Invalid algorithm\n");
		return -1;
	}

	for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
            in = argv[i+1];
            inCheck = 1;
            i++;
        }
        else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
            out = argv[i+1];
            outCheck = 1;
            i++;
        }
#ifdef HAVE_BLAKE
        else if (strcmp(argv[i], "-s") == 0 && argv[i+1] != NULL) {
            size = atoi(argv[i+1]);
            if (size <= 0 || size > 64) {
                printf("Invalid size, Must be between 0-64. Using default.\n");
                size = BLAKE_DIGEST_SIZE;
            }
            i++;
        }
#endif
        else {
            printf("Unknown argument %s. Ignoring\n", argv[i]);
        }
    }
    if (inCheck == 0) {
        printf("Must have input as either a file or standard I/O\n");
        return -1;
    }
    if (outCheck == 0) {
    	out = malloc(strlen(in) + 1 + strlen(alg));
        alg = strtok(alg, "-");
        strcpy(out, in);
        strcat(out, ".");
        strcat(out, alg);
    }
	switch(num) {
#ifndef NO_MD5
        case 0:
        HashMd5(in, out);
            break;
#endif

#ifndef NO_SHA
        case 1:
        HashSha(in, out);
            break;
#endif

#ifndef NO_SHA256
        case 2:
        HashSha256(in, out);
            break;
#endif

#ifdef CYASSL_SHA384
        case 3:
        HashSha384(in, out);
            break;
#endif

#ifdef CYASSL_SHA512
        case 4:
        HashSha512(in, out);
            break;
#endif

#ifdef HAVE_BLAKE2
        case 5:
        HashBlake2b(in, out, size);
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

int Bench(int argc, char** argv)
{
    int ret = 0;
    int time = 3;
    int i = 0;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            printf("\nUsage: cyassl benchmark [-t timer(1-10)]\nCurrently ");
            printf("tests all available features of the cyassl utility.\n\n");
            return -1;
        }
        if (strcmp(argv[i], "-t") == 0 && argv[i+1] != NULL) {
            time = atoi(argv[i+1]);
            if (time <= 1 || time > 10) {
                printf("Invalid time, must be between 1-10. Using default.\n");
                time = 3;
            }
            i++;
        }
        else {
            printf("Unknown argument %s. Ignoring\n", argv[i]);
        }
    }
    printf("\nTesting for %d seconds each\n", time);
    ret = Benchmark(time);

    return ret;
}

int GetAlgorithm(char* name, char** alg, char** mode, int* size)
{
	int 	ret = 0;
    int     i;
    int     nameCheck = 0;
	int     modeCheck = 0;
    char*	sz = 0;
    char* acceptAlgs[] = {"aes", "3des", "camellia"};

	*alg = strtok(name, "-");
    for (i = 0; i < 3; i++) {
        if (strcmp(*alg, acceptAlgs[i]) == 0 )
            nameCheck = 1;
    }
    *mode = strtok(NULL, "-");
    if (strcmp(*mode, "cbc") == 0)
        modeCheck = 1;

    if (nameCheck == 0 || modeCheck == 0) {
        printf("Invalid entry. Please enter -help for help\n");
        return -1;
    }

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

#ifdef HAVE_CAMELLIA
	else if (strcmp(*alg, "camellia") == 0) {
	    ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            /* if the entered size does not match acceptable size */
            printf("Invalid Camellia key size\n");
            ret = -1;
        }
	}
#endif

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

void Stopf(int signo)
{
    loop = 0;
}

double CurrTime(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

void Stats(double start, int blockSize)
{
    int64_t compBlocks = blocks;
    double total = CurrTime() - start, mbs;

    printf("took %6.3f seconds, blocks = %llu\n", total,
           (unsigned long long)compBlocks);

    mbs = compBlocks * blockSize / MEGABYTE / total;
    printf("MB/s = %8.1f\n", mbs);
}

int Encrypt(char* alg, char* mode, byte* key, int size, char* in, char* out, 
	byte* iv, int block)
{
	Aes aes;
	Des3 des3;

#ifdef HAVE_CAMELLIA
	Camellia camellia;
#endif
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

#ifdef HAVE_CAMELLIA
	if (strcmp(alg, "camellia") == 0) {
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return -1001;
	    CamelliaCbcEncrypt(&camellia, output, input, length);
	}
#endif /* HAVE_CAMELLIA */

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

#ifdef HAVE_CAMELLIA
	Camellia camellia;
#endif

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

#ifdef HAVE_CAMELLIA
	if (strcmp(alg, "camellia") == 0) {
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return -1001;
	    /* encrypts the message to the ouput based on input length + padding */
	    CamelliaCbcDecrypt(&camellia, output, input, length);
	}
#endif /* HAVE_CAMELLIA */

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

int Benchmark(int timer)
{
    Aes aes;
	Des3 des3;

    RNG rng;

    int ret = 0;
    double start;
    ALIGN16 byte* plain;
    ALIGN16 byte* cipher;
    ALIGN16 byte* key;
    ALIGN16 byte* iv;
    byte* digest;

    InitRng(&rng);

    signal(SIGALRM, Stopf);

    plain = malloc(AES_BLOCK_SIZE);
    cipher = malloc(AES_BLOCK_SIZE);
    key = malloc(AES_BLOCK_SIZE);
    iv = malloc(AES_BLOCK_SIZE);

    RNG_GenerateBlock(&rng, plain, AES_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, cipher, AES_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, key, AES_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);

    start = CurrTime();
    alarm(timer);
                   
    AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    while (loop) {
        AesCbcEncrypt(&aes, cipher, plain, AES_BLOCK_SIZE);
        blocks++;
    }
    printf("AES ");
    Stats(start, AES_BLOCK_SIZE);
    memset(plain, 0, AES_BLOCK_SIZE);
    memset(cipher, 0, AES_BLOCK_SIZE);
    memset(key, 0, AES_BLOCK_SIZE);
    memset(iv, 0, AES_BLOCK_SIZE);
    free(plain);
    free(cipher);
    free(key);
    free(iv);
    blocks = 0;
    loop = 1;
   
    plain = malloc(DES3_BLOCK_SIZE);
    cipher = malloc(DES3_BLOCK_SIZE);
    key = malloc(DES3_BLOCK_SIZE);
    iv = malloc(DES3_BLOCK_SIZE);
    
    RNG_GenerateBlock(&rng, plain, DES3_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, cipher, DES3_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, key, DES3_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, iv, DES3_BLOCK_SIZE);
 
    start = CurrTime();
    alarm(timer);

       Des3_SetKey(&des3, key, iv, DES_ENCRYPTION);
    while (loop) {
        Des3_CbcEncrypt(&des3, cipher, plain, DES3_BLOCK_SIZE);
        blocks++;
    }
    printf("3DES ");
    Stats(start, DES3_BLOCK_SIZE);
    memset(plain, 0, DES3_BLOCK_SIZE);
    memset(cipher, 0, DES3_BLOCK_SIZE);
    memset(key, 0, DES3_BLOCK_SIZE);
    memset(iv, 0, DES3_BLOCK_SIZE);
    free(plain);
    free(cipher);
    free(key);
    free(iv);
    blocks = 0;
    loop = 1;
    
#ifdef HAVE_CAMELLIA
	Camellia camellia;

    plain = malloc(CAMELLIA_BLOCK_SIZE);
    cipher = malloc(CAMELLIA_BLOCK_SIZE);
    key = malloc(CAMELLIA_BLOCK_SIZE);
    iv = malloc(CAMELLIA_BLOCK_SIZE);
  
    RNG_GenerateBlock(&rng, plain, CAMELLIA_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, cipher, CAMELLIA_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, key, CAMELLIA_BLOCK_SIZE);
    RNG_GenerateBlock(&rng, iv, CAMELLIA_BLOCK_SIZE);
  
    start = CurrTime();
    alarm(timer);

    CamelliaSetKey(&camellia, key, CAMELLIA_BLOCK_SIZE, iv);
    while (loop) {
        CamelliaCbcEncrypt(&camellia, cipher, plain, CAMELLIA_BLOCK_SIZE);
        blocks++;
    }
    printf("Camellia ");
    Stats(start, CAMELLIA_BLOCK_SIZE);
    memset(plain, 0, CAMELLIA_BLOCK_SIZE);
    memset(cipher, 0, CAMELLIA_BLOCK_SIZE);
    memset(key, 0, CAMELLIA_BLOCK_SIZE);
    memset(iv, 0, CAMELLIA_BLOCK_SIZE);
    free(plain);
    free(cipher);
    free(key);
    free(iv);
    blocks = 0;
    loop = 1;
#endif

#ifndef NO_MD5
    Md5 md5;

    digest = malloc(MD5_DIGEST_SIZE);
    plain = malloc(MEGABYTE);
    RNG_GenerateBlock(&rng, plain, MEGABYTE);

    InitMd5(&md5);
    start = CurrTime();
    alarm(timer);

    while (loop) {
        Md5Update(&md5, plain, MEGABYTE);
        blocks++;
    }
    Md5Final(&md5, digest);
    printf("MD5 ");
    Stats(start, MEGABYTE);
    memset(plain, 0, MEGABYTE);
    memset(digest, 0, MD5_DIGEST_SIZE);
    free(plain);
    free(digest);
    blocks = 0;
    loop = 1;
#endif

#ifndef NO_SHA
    Sha sha;

    digest = malloc(SHA_DIGEST_SIZE);
    plain = malloc(MEGABYTE);
    RNG_GenerateBlock(&rng, plain, MEGABYTE);

    InitSha(&sha);
    start = CurrTime();
    alarm(timer);

    while (loop) {
        ShaUpdate(&sha, plain, MEGABYTE);
        blocks++;
    }
    ShaFinal(&sha, digest);
    printf("Sha ");
    Stats(start, MEGABYTE);
    memset(plain, 0, MEGABYTE);
    memset(digest, 0, SHA_DIGEST_SIZE);
    free(plain);
    free(digest);
    blocks = 0;
    loop = 1;
#endif

#ifndef NO_SHA256
    Sha256 sha256;

    digest = malloc(SHA256_DIGEST_SIZE);
    plain = malloc(MEGABYTE);
    RNG_GenerateBlock(&rng, plain, MEGABYTE);

    InitSha256(&sha256);
    start = CurrTime();
    alarm(timer);

    while (loop) {
        Sha256Update(&sha256, plain, MEGABYTE);
        blocks++;
    }
    Sha256Final(&sha256, digest);
    printf("Sha256 ");
    Stats(start, MEGABYTE);
    memset(plain, 0, MEGABYTE);
    memset(digest, 0, SHA256_DIGEST_SIZE);
    free(plain);
    free(digest);
    blocks = 0;
    loop = 1;

#endif

#ifdef CYASSL_SHA384
    Sha384 sha384;

    digest = malloc(SHA384_DIGEST_SIZE);
    plain = malloc(MEGABYTE);
    RNG_GenerateBlock(&rng, plain, MEGABYTE);

    InitSha384(&sha384);
    start = CurrTime();
    alarm(timer);

    while (loop) {
        Sha384Update(&sha384, plain, MEGABYTE);
        blocks++;
    }
    Sha384Final(&sha384, digest);
    printf("Sha384 ");
    Stats(start, MEGABYTE);
    memset(plain, 0, MEGABYTE);
    memset(digest, 0, SHA384_DIGEST_SIZE);
    free(plain);
    free(digest);
    blocks = 0;
    loop = 1;

#endif

#ifdef CYASSL_SHA512
    Sha512 sha512;

    digest = malloc(SHA512_DIGEST_SIZE);
    plain = malloc(MEGABYTE);
    RNG_GenerateBlock(&rng, plain, MEGABYTE);

    InitSha512(&sha512);
    start = CurrTime();
    alarm(timer);

    while (loop) {
        Sha512Update(&sha512, plain, MEGABYTE);
        blocks++;
    }
    Sha512Final(&sha512, digest);
    printf("Sha512 ");
    Stats(start, MEGABYTE);
    memset(plain, 0, MEGABYTE);
    memset(digest, 0, SHA512_DIGEST_SIZE);
    free(plain);
    free(digest);
    blocks = 0;
    loop = 1;
#endif

#ifdef HAVE_BLAKE2
    Blake2b  b2b;

    digest = malloc(BLAKE_DIGEST_SIZE);
    plain = malloc(MEGABYTE);
    RNG_GenerateBlock(&rng, plain, MEGABYTE);

    InitBlake2b(&b2b, BLAKE_DIGEST_SIZE);
    start = CurrTime();
    alarm(timer);

    while (loop) {
        Blake2bUpdate(&b2b, plain, MEGABYTE);
        blocks++;
    }
    Blake2bFinal(&b2b, digest, BLAKE_DIGEST_SIZE);
    printf("Blake2b ");
    Stats(start, MEGABYTE);
    memset(plain, 0, MEGABYTE);
    memset(digest, 0, BLAKE_DIGEST_SIZE);
    free(plain);
    free(digest);
#endif
    return ret;
}

#ifndef NO_MD5
int HashMd5(char* in, char* out)
{
    Md5 hash;
    FILE*  inFile;
    FILE*  outFile;

    byte*   input;
    byte*   output;

    int length;
    int ret;

    InitMd5(&hash);

    inFile = fopen(in, "r");
    if (inFile == NULL) {
        printf("Input file does not exist\n");
        return -1;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    input = malloc(length);
    output = malloc(MD5_DIGEST_SIZE);

    ret = fread(input, 1, length, inFile);

    Md5Update(&hash, input, length);
    Md5Final(&hash, output);

    fwrite(output, 1, MD5_DIGEST_SIZE, outFile);

    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return ret;
}
#endif /* NO_MD5 */

#ifndef NO_SHA
int HashSha(char* in, char* out)
{
    Sha hash;
    FILE*  inFile;
    FILE*  outFile;

    byte*   input;
    byte*   output;

    int length;
    int ret;

    InitSha(&hash);

    inFile = fopen(in, "r");
    if (inFile == NULL) {
        printf("Input file does not exist\n");
        return -1;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    input = malloc(length);
    output = malloc(SHA_DIGEST_SIZE);

    ret = fread(input, 1, length, inFile);

    ShaUpdate(&hash, input, length);
    ShaFinal(&hash, output);

    fwrite(output, 1, SHA_DIGEST_SIZE, outFile);

    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return ret;
}
#endif /* NO_SHA */

#ifndef NO_SHA256
int HashSha256(char* in, char* out)
{
    Sha256 hash;
    FILE*  inFile;
    FILE*  outFile;

    byte*   input;
    byte*   output;

    int length;
    int ret;

    InitSha256(&hash);

    inFile = fopen(in, "r");
    if (inFile == NULL) {
        printf("Input file does not exist\n");
        return -1;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    input = malloc(length);
    output = malloc(SHA256_DIGEST_SIZE);

    ret = fread(input, 1, length, inFile);

    Sha256Update(&hash, input, length);
    Sha256Final(&hash, output);

    fwrite(output, 1, SHA256_DIGEST_SIZE, outFile);

    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return ret;
}
#endif /* NO_SHA256 */

#ifdef CYASSL_SHA384
int HashSha384(char* in, char* out)
{
    Sha384 hash;
    FILE*  inFile;
    FILE*  outFile;

    byte*   input;
    byte*   output;

    int length;
    int ret;

    InitSha384(&hash);

    inFile = fopen(in, "r");
    if (inFile == NULL) {
        printf("Input file does not exist\n");
        return -1;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    input = malloc(length);
    output = malloc(SHA384_DIGEST_SIZE);

    ret = fread(input, 1, length, inFile);

    Sha384Update(&hash, input, length);
    Sha384Final(&hash, output);

    fwrite(output, 1, SHA384_DIGEST_SIZE, outFile);

    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return ret;
}
#endif /* CYASSL_SHA384 */

#ifdef CYASSL_SHA512
int HashSha512(char* in, char* out)
{
    Sha512 hash;
    FILE*  inFile;
    FILE*  outFile;

    byte*   input;
    byte*   output;

    int length;
    int ret;

    InitSha512(&hash);

    inFile = fopen(in, "r");
    if (inFile == NULL) {
        printf("Input file does not exist\n");
        return -1;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    input = malloc(length);
    output = malloc(SHA512_DIGEST_SIZE);

    ret = fread(input, 1, length, inFile);

    Sha512Update(&hash, input, length);
    Sha512Final(&hash, output);

    fwrite(output, 1, SHA512_DIGEST_SIZE, outFile);

    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return ret;
}
#endif /* CYASSL_SHA512 */

#ifdef HAVE_BLAKE2
int HashBlake2b(char* in, char* out, int size)
{
    Blake2b hash;
    FILE*  inFile;
    FILE*  outFile;

    byte*   input;
    byte*   output;

    int length;
    int ret;

    if (size == 0) 
    {
        size = BLAKE_DIGEST_SIZE;
    }
    InitBlake2b(&hash, size);

    inFile = fopen(in, "r");
    if (inFile == NULL) {
            printf("Input file does not exist\n");
            return -1;
    }
    outFile = fopen(out, "w");

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    input = malloc(length);
    output = malloc(size);

    ret = fread(input, 1, length, inFile);
   
    Blake2bUpdate(&hash, input, length);
    Blake2bFinal(&hash, output, size);

    fwrite(output, 1, BLAKE_DIGEST_SIZE, outFile);

    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return ret;
}
#endif /* HAVE_BLAKE2 */

