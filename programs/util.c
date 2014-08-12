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

int     loop    = 1;            /* benchmarking loop */
int     i       = 0;            /* loop variable */
int64_t blocks;                 /* blocks used during benchmarking */

/*
 * encryption argument function
 */
int Enc(int argc, char** argv)
{
    char*    name;              /* string of algorithm, mode, keysize */
    char*    alg;               /* algorithm from name */
    char*    mode;              /* mode from name */
    char*    in;                /* input file/text provided */
    char*    out;               /* output file if provided */
    byte*    key;               /* password for generating key */
    byte*    iv;                /* iv for initial encryption */

    char     outName[256] = "encrypted"; /* name for outFile if not provided */
    int      size       =   0;  /* keysize from name */
    int      ret        =   0;  /* return variable */
    int      block      =   0;  /* block size based on algorithm */
    int      keyCheck   =   0;  /* if a key has been provided */
    int      inCheck    =   0;  /* if input has been provided */
    int      outCheck   =   0;  /* if output has been provided */
    int      mark       =   0;  /* used for getting file extension of in */

    /* help checking */
    if (argc == 2) {
        Help("encrypt");
        return 0;
    }

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            Help("encrypt");
            return 0;
        }
    }

    name = argv[2];
    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = GetAlgorithm(name, &alg, &mode, &size);
    
    if (block != FATAL_ERROR) {
        key = malloc(size);
        iv = malloc(block);
        memset(iv, 0, block);

        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
                /* input file/text */
                in = argv[i+1];
                inCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
                /* output file */
                out = argv[i+1];
                outCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-k") == 0 && argv[i+1] != NULL) {
                /* password key */
                memcpy(key, argv[i+1], size);
                keyCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-iv") == 0 && argv[i+1] != NULL) {
                /* iv for encryption */
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
            /* if no input is provided */
            printf("Must have input as either a file or standard I/O\n");
            return FATAL_ERROR;
        }
        if (keyCheck == 0) {
            /* if no key is provided */
            ret = NoEcho((char*)key, size);
        }
        if (outCheck == 0 && ret == 0) {
            out = outName;
            /* gets file extension of input type */
            for (i = 0; i < strlen(in); i++) {
                if ((in[i] == '.') || (mark == 1)) {
                    mark = 1;
                    Append(out, in[i]);
                }
            }
        }
        /* encryption function */
        ret = Encrypt(alg, mode, key, size, in, out, iv, block);

        /* clear and free data */
        memset(key, 0, size);
        memset(iv, 0, block);
        free(key);
        free(iv);
    }
    else
        ret = FATAL_ERROR;
    return ret;
}

/*
 * decryption argument function
 */ 
int Dec(int argc, char** argv)
{
    char*    name;              /* string of algorithm, mode, keysize */
    char*    alg;               /* algorithm from name */
    char*    mode;              /* mode from name */
    char*    in;                /* input file/text provided */
    char*    out;               /* output file if provided */
    byte*    key;               /* password for generating key */
    byte*    iv;                /* iv for initial encryption */

    char     outName[256] = "decrypted"; /* name for outFile if not provided */
    int      size       =  0;   /* keysize from name */
    int      ret        =  0;   /* return variable */
    int      block      =  0;   /* block size based on algorithm */
    int      keyCheck   =  0;   /* if a key has been provided */
    int      inCheck    =  0;   /* if input has been provided */
    int      outCheck   =  0;   /* if output has been provided */
    int      mark       =  0;   /* used for getting file extension of in */

    /* help checking */
    if (argc == 2) {
        Help("decrypt");
        return 0;
    }

    for (i = 2; i < argc; i++) {
       if (strcmp(argv[i], "-help") == 0) {
           Help("decrypt");
           return 0;
        }
    }

    name = argv[2];
    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = GetAlgorithm(name, &alg, &mode, &size);

    if (block != FATAL_ERROR) {
        key = malloc(size);
        iv = malloc(block);
        memset(iv, 0, block);

        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
                /* input file/text */
                in = argv[i+1];
                inCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
                /* output file */
                out = argv[i+1];
                outCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-k") == 0 && argv[i+1] != NULL) {
                /* password key */
                memcpy(key, argv[i+1], size);
                keyCheck = 1;
                i++;
            }
            else if (strcmp(argv[i], "-iv") == 0 && argv[i+1] != NULL) {
                /* iv for decryption */
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
            /* if no input is provided */
            printf("Must have input as a file\n");
            return FATAL_ERROR;
        }
        if (keyCheck == 0) {
            /* if no key is provided */
            ret = NoEcho((char*)key, size);
        }
        if (outCheck == 0 && ret == 0) {
            out = outName;
            /* gets file type of input file */
            for (i = 0; i < strlen(in); i++) {
                if ((in[i] == '.') || (mark == 1)) {
                    mark = 1;
                    Append(out, in[i]);
                }
            }
        }
        /* decryption function */
        ret = Decrypt(alg, mode, key, size, in ,out, iv, block);
        
        /* clear and free data */
        memset(key, 0, size);
        memset(iv, 0, block);
        free(key);
        free(iv);
    }
    else 
        ret = FATAL_ERROR;
    return ret;
}

/*
 * help function
 */ 
void Help(char* name)
{
    if (strcmp(name, "hash") == 0) {
        /* hash help prints hash options */
        char* algs[] = {        /* list of acceptable algorithms */
#ifndef NO_MD5
            "-md5"
#endif
#ifndef NO_SHA
            ,"-sha"
#endif
#ifndef NO_SHA256
            ,"-sha256"
#endif
#ifdef CYASSL_SHA384
            ,"-sha384"
#endif
#ifdef CYASSL_SHA512
            ,"-sha512"
#endif
#ifdef HAVE_BLAKE2
            ,"-blake2b"
#endif
        };

        printf("\nUSAGE: cyassl hash <-algorithm> <-i filename> [-o filename]"
                " [-s size]\n");
        printf("\n( NOTE: *size use for Blake2b only between 1-64)\n");
        printf("\nAcceptable Algorithms\n");
        for (i = 0; i < sizeof(algs)/sizeof(algs[0]); i++) {
            printf("%s\n", algs[i]);
        }
        printf("\n");
    }
    else if (strcmp(name, "bench") == 0) {
        /* benchmark help lists benchmark options */
        char* algs[] = {        /* list of acceptable algorithms */
#ifndef NO_AES
            "-aes-cbc"
#endif
#ifdef CYASSL_AES_COUNTER
            , "-aes-ctr"
#endif
#ifndef NO_DES3
            , "-3des"
#endif
#ifdef HAVE_CAMELLIA
            , "-camellia"
#endif
#ifndef NO_MD5
            , "-md5"
#endif
#ifndef NO_SHA
            , "-sha"
#endif
#ifndef NO_SHA256
            , "-sha256"
#endif
#ifdef CYASSL_SHA384
            , "-sha384"
#endif
#ifdef CYASSL_SHA512
            , "-sha512"
#endif
#ifdef HAVE_BLAKE2
            , "-blake2b"
#endif
        };
        printf("\nUsage: cyassl benchmark [-t timer(1-10)] [-alg]\n");
        printf("\nAvailable tests: (-all to test all)\n");

        for(i = 0; i < sizeof(algs)/sizeof(algs[0]); i++) {
            printf("%s\n", algs[i]);
        }
        printf("\n");
    }
    else {
        /* encryption/decryption help lists options */
        printf("\nUSAGE: cyassl %s <-algorithm> <-i filename> ", name);
        printf("[-o filename] [-k password] [-iv IV]\n\n"
               "Acceptable Algorithms");
#ifndef NO_AES
        printf("\n-aes-cbc-128\t\t-aes-cbc-192\t\t-aes-cbc-256\n");
#endif
#ifdef CYASSL_AES_COUNTER
        printf("-aes-ctr-128\t\t-aes-ctr-192\t\t-aes-ctr-256\n");
#endif
#ifndef NO_DES3
        printf("-3des-cbc-56\t\t-3des-cbc-112\t\t-3des-cbc-168\n");
#endif
#ifdef HAVE_CAMELLIA
        printf("-camellia-cbc-128\t-camellia-cbc-192\t"
               "-camellia-cbc-256\n");
#endif
        printf("\n");
    }
}

/*
 * hash argument function
 */
int Has(int argc, char** argv)
{
	int     ret     =   0;      /* return variable */
    char*   in;                 /* input variable */
    char*   out     =   NULL;   /* output variable */
	char*   algs[]  =   {       /* list of acceptable algorithms */
#ifndef NO_MD5
        "-md5"
#endif
#ifndef NO_SHA
        ,"-sha"
#endif
#ifndef NO_SHA256
        ,"-sha256"
#endif
#ifdef CYASSL_SHA384
        ,"-sha384"
#endif
#ifdef CYASSL_SHA512
        ,"-sha512"
#endif
#ifdef HAVE_BLAKE2
        ,"-blake2b"
#endif
        };

	char*   alg;                /* algorithm being used */
    int     algCheck=   0;      /* acceptable algorithm check */
	int     inCheck =   0;      /* input check */
    int     size    =   0;      /* message digest size */           
    char*   len     =   NULL;   /* length to be hashed */

#ifdef HAVE_BLAKE2
    size = BLAKE_DIGEST_SIZE;
#endif

    /* help checking */
    if (argc == 2) {
        Help("hash");
        return 0;
    }
	for (i = 2; i < argc; i++) {
       if (strcmp(argv[i], "-help") == 0) {
            Help("hash");
            return 0;
        }
    }

    for (i = 0; i < sizeof(algs)/sizeof(algs[0]); i++) {
        /* checks for acceptable algorithms */
		if (strcmp(argv[2], algs[i]) == 0) {
			alg = argv[2];
            algCheck = 1;
		}
	}
	if (algCheck == 0) {
		printf("Invalid algorithm\n");
		return FATAL_ERROR;
	}

	for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
            /* input file/text */
            in = malloc(strlen(argv[i+1])+1);
            strcpy(in, &argv[i+1][0]);
            in[strlen(argv[i+1])] = '\0';
            inCheck = 1;
            i++;
        }
        else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
            /* output file */
            out = argv[i+1];
            i++;
        }
        else if (strcmp(argv[i], "-s") == 0 && argv[i+1] != NULL) {
            /* size of output */
#ifndef HAVE_BLAKE2
            printf("Sorry, only to be used with Blake2b enabled\n");
#else
            size = atoi(argv[i+1]);
            if (size <= 0 || size > 64) {
                printf("Invalid size, Must be between 1-64. Using default.\n");
                size = BLAKE_DIGEST_SIZE;
            }
#endif
            i++;
        }
        else if (strcmp(argv[i], "-l") == 0) {
            /* length of string to hash */
            len = malloc(strlen(argv[i+1])+1);
            strcpy(len, &argv[i+1][0]);
            len[strlen(argv[i+1])] = '\0';
            i++;
        } 
        else {
            printf("Unknown argument %s. Ignoring\n", argv[i]);
        }
    }
    if (inCheck == 0) {
        printf("Must have input as either a file or standard I/O\n");
        return FATAL_ERROR;
    }
    /* sets default size of algorithm */
#ifndef NO_MD5
    if (strcmp(alg, "-md5") == 0) 
        size = MD5_DIGEST_SIZE;
#endif

#ifndef NO_SHA
    if (strcmp(alg, "-sha") == 0) 
        size = SHA_DIGEST_SIZE;
#endif

#ifndef NO_SHA256
    if (strcmp(alg, "-sha256") == 0) 
        size = SHA256_DIGEST_SIZE;
#endif

#ifdef CYASSL_SHA384
    if (strcmp(alg, "-sha384") == 0)
        size = SHA384_DIGEST_SIZE;
#endif

#ifdef CYASSL_SHA512
    if (strcmp(alg, "-sha512") == 0)
        size = SHA512_DIGEST_SIZE;
#endif

    /* hashing function */
    Hash(in, len, out, alg, size);

    free(in);
    free(len);
    
	return ret;
}

/*
 * benchmark argument function
 */
int Bench(int argc, char** argv)
{
    int     ret     =   0;      /* return variable */
    int     time    =   3;      /* timer variable */
    int     j       =   0;      /* second loop variable */
    char*   algs[]  =   {       /* list of acceptable algorithms */
#ifndef NO_AES
        "-aes-cbc"
#endif
#ifdef CYASSL_AES_COUNTER
        , "-aes-ctr"
#endif
#ifndef NO_DES3
        , "-3des"
#endif
#ifdef HAVE_CAMELLIA
        , "-camellia"
#endif
#ifndef NO_MD5
        , "-md5"
#endif
#ifndef NO_SHA
        , "-sha"
#endif
#ifndef NO_SHA256
        , "-sha256"
#endif
#ifdef CYASSL_SHA384
        , "-sha384"
#endif
#ifdef CYASSL_SHA512
        , "-sha512"
#endif
#ifdef HAVE_BLAKE2
        , "-blake2b"
#endif
        };

    int option[sizeof(algs)/sizeof(algs[0])] = {0};/* acceptable options */
    int optionCheck = 0;                           /* acceptable option check */

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            /* help checking */
            Help("bench");
            return 0;
        }
        for (j = 0; j < sizeof(algs)/sizeof(algs[0]); j++) {
            /* checks for individual tests in the arguments */
            if (strcmp(argv[i], algs[j]) == 0) {
                option[j] = 1;    
                optionCheck = 1;
            }
        }

        if (strcmp(argv[i], "-t") == 0 && argv[i+1] != NULL) {
            /* time for each test in seconds */
            time = atoi(argv[i+1]);
            if (time < 1 || time > 10) {
                printf("Invalid time, must be between 1-10. Using default.\n");
                time = 3;
            }
            i++;
        }
        if (strcmp(argv[i], "-all") == 0) {
            /* perform all available tests */
            for (j = 0; j < sizeof(algs)/sizeof(algs[0]); j++) {
                option[j] = 1;
                optionCheck = 1;
            }
        }
    }
    if (optionCheck != 1) {
        /* help checking */
        Help("bench");
    }
    else {
        /* benchmarking function */
        printf("\nTesting for %d second(s)\n", time);
        ret = Benchmark(time, option);
    }
    return ret;
}

/*
 * finds algorithm for encryption/decryption
 */
int GetAlgorithm(char* name, char** alg, char** mode, int* size)
{
	int 	ret         = 0;        /* return variable */
    int     nameCheck   = 0;        /* check for acceptable name */
	int     modeCheck   = 0;        /* check for acceptable mode */
    char*	sz          = 0;        /* key size provided */
    char* acceptAlgs[]  = {         /* list of acceptable algorithms */
#ifndef NO_AES
        "aes"
#endif
#ifndef NO_DES3
        , "3des"
#endif
#ifdef HAVE_CAMELLIA
        , "camellia"
#endif
                        };
    char* acceptMode[] = {"cbc"
#ifdef CYASSL_AES_COUNTER
        , "ctr"
#endif
    };

    /* gets name after first '-' and before the second */
	*alg = strtok(name, "-");
    for (i = 0; i < sizeof(acceptAlgs)/sizeof(acceptAlgs[0]); i++) {
        if (strcmp(*alg, acceptAlgs[i]) == 0 )
            nameCheck = 1;
    }
    /* gets mode after second "-" and before the third */
    if (nameCheck != 0) {
        *mode = strtok(NULL, "-");
        for (i = 0; i < sizeof(acceptMode)/sizeof(acceptMode[0]); i++) {
            if (strcmp(*mode, acceptMode[i]) == 0)
                modeCheck = 1;
            }
    }
    /* if name or mode doesn't match acceptable options */
    if (nameCheck == 0 || modeCheck == 0) {
        printf("Invalid entry\n");
        return FATAL_ERROR;
    }

    /* gets size after thrid "-" */
	sz = strtok(NULL, "-");
	*size = atoi(sz);
    
    /* checks key sizes for acceptability */
#ifndef NO_AES
	if (strcmp(*alg, "aes") == 0) {
		ret = AES_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            printf("Invalid AES key size\n");
            ret = FATAL_ERROR;
        }
	}
#endif
#ifndef NO_DES3
	else if (strcmp(*alg, "3des") == 0) {
		ret = DES3_BLOCK_SIZE;
        if (*size != 56 && *size != 112 && *size != 168) {
            printf("Invalid 3DES key size\n");
            ret = FATAL_ERROR;
        }
	}
#endif
#ifdef HAVE_CAMELLIA
	else if (strcmp(*alg, "camellia") == 0) {
	    ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            printf("Invalid Camellia key size\n");
            ret = FATAL_ERROR;
        }
	}
#endif

	else {
		printf("Invalid algorithm: %s\n", *alg);
		ret = FATAL_ERROR;
	}
	return ret;
}

/*
 * makes a cyptographically secure key by stretching a user entered key
 */
int GenerateKey(RNG* rng, byte* key, int size, byte* salt, int pad)
{
    int ret;        /* return variable */

    /* randomly generates salt */
    ret = RNG_GenerateBlock(rng, salt, SALT_SIZE-1);
    if (ret != 0)
        return ret;

    if (pad == 0)        /* sets first value of salt to check if the */
        salt[0] = 0;            /* message is padded */

    /* stretches key */
    ret = PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096, 
        size, SHA256);
    if (ret != 0)
        return ret;

    return 0;
}

/*
 * secure data entry by turning off key echoing in the terminal
 */
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
        return FATAL_ERROR;
    }

    printf("Key: ");
    fgets(key, size, stdin);
    key[strlen(key) - 1] = 0;
    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        printf("Error\n");
        return FATAL_ERROR;
    }
    return 0;
}

/*
 * adds character to end of string 
 */
void Append(char* s, char c)
{
    int len = strlen(s); /* length of string*/

    s[len] = c;
    s[len+1] = '\0';
}

/*
 * resets benchmarking loop
 */
void Stopf(int signo)
{
    loop = 0;
}

/*
 * gets current time durring program execution
 */
double CurrTime(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

/* 
 * prints out stats for benchmarking
 */
void Stats(double start, int blockSize)
{
    int64_t compBlocks = blocks;
    double total = CurrTime() - start, mbs;

    printf("took%6.3f seconds, blocks = %llu\n", total,
           (unsigned long long)compBlocks);

    mbs = compBlocks * blockSize / MEGABYTE / total;
    printf("Average MB/s = %8.1f\n", mbs);
}

/*
 * encryption funciton
 */
int Encrypt(char* alg, char* mode, byte* key, int size, char* in, char* out, 
	byte* iv, int block)
{
#ifndef NO_AES
	Aes aes;                        /* aes declaration */
#endif

#ifndef NO_DES3
	Des3 des3;                      /* 3des declaration */
#endif

#ifdef HAVE_CAMELLIA
	Camellia camellia;              /* camellia declaration */
#endif
	FILE*  inFile;                  /* input file */
    FILE*  outFile;                 /* output file */

	RNG     rng;                    /* random number generator declaration */
    byte*   input;                  /* input buffer */
    byte*   output;                 /* output buffer */
    byte    salt[SALT_SIZE] = {0};  /* salt variable */

    int     ret             = 0;    /* return variable */
    int     inputLength;            /* length of input */
    int     length;                 /* total length */
    int     padCounter = 0;         /* number of padded elements */
    int 	fileCheck = 0;          /* if a file has been provided for input */

	inFile = fopen(in, "r");
	if (inFile != NULL) {
		/* if there is a file. find length */
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
        if (ret != inputLength) {
            return FREAD_ERROR;
        }
	}
	else {
		/* else use user entered data to encrypt */
		inputLength = strlen(in);
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
        /* randomly generate iv if one has not been provided */
    	ret = RNG_GenerateBlock(&rng, iv, block);
    	if (ret != 0)
        	return ret;
	}
    /* stretches key to fit size */
    ret = GenerateKey(&rng, key, size, salt, padCounter);
    if (ret != 0) 
        return ret;

    /* sets key encrypts the message to ouput from input length + padding */
#ifndef NO_AES
    if (strcmp(alg, "aes") == 0) {
        if (strcmp(mode, "cbc") == 0) {
		    ret = AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
	        if (ret != 0)
	            return ret;
	        ret = AesCbcEncrypt(&aes, output, input, length);
	        if (ret != 0)
    	        return ENCRYPT_ERROR;
        }
#ifdef CYASSL_AES_COUNTER
        else if (strcmp(mode, "ctr") == 0) {
            /* if mode is ctr */
            AesSetKeyDirect(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
            AesCtrEncrypt(&aes, output, input, length);
        }
#endif
	}
#endif
#ifndef NO_DES3
	if (strcmp(alg, "3des") == 0) {
		ret = Des3_SetKey(&des3, key, iv, DES_ENCRYPTION);
	    if (ret != 0)
	        return ret;
        ret = Des3_CbcEncrypt(&des3, output, input, length);
	    if (ret != 0)
	        return ENCRYPT_ERROR;
	}
#endif
#ifdef HAVE_CAMELLIA
	if (strcmp(alg, "camellia") == 0) {
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return ret;
        if (strcmp(mode, "cbc") == 0) {
	        CamelliaCbcEncrypt(&camellia, output, input, length);
        }
        else {
            printf("Incompatible mode\n");
            return FATAL_ERROR;
        }
	}
#endif /* HAVE_CAMELLIA */

    /* writes to outFile */
    fwrite(salt, 1, SALT_SIZE, outFile);
    fwrite(iv, 1, block, outFile);
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory */
    memset(input, 0, length);
    memset(output, 0, length);
    memset(key, 0, size);
    memset(iv, 0 , block);
    memset(alg, 0, size);
    memset(mode, 0 , block);
    free(input);
    free(output);
    if(fileCheck == 1)      /* if a file was used for input */
    	fclose(inFile);
    fclose(outFile);
    return 0;
}

/*
 * decryption function
 */
int Decrypt(char* alg, char* mode, byte* key, int size, char* in, char* out, 
	byte* iv, int block)
{
#ifndef NO_AES
	Aes aes;                        /* aes declaration */
#endif

#ifndef NO_DES3
	Des3 des3;                      /* 3des declaration */
#endif

#ifdef HAVE_CAMELLIA
	Camellia camellia;              /* camellia declaration */
#endif

	FILE*  inFile;                  /* input file */
    FILE*  outFile;                 /* output file */

	RNG     rng;                    /* random number generator */
    byte*   input;                  /* input buffer */
    byte*   output;                 /* output buffer */
    byte    salt[SALT_SIZE] = {0};  /* salt variable */

    int     ret     = 0;            /* return variable */
    int     length;                 /* length of message */
    int 	aSize   = 0;            /* actual size of message */

    /* opens input file */
    inFile = fopen(in, "r");
	if (inFile == NULL) {
        printf("Input file does not exist.\n");
        return DECRYPT_ERROR;
    }
    /* opens output file */
    outFile = fopen(out, "w");
    if (outFile == NULL) {
        printf("Error creating output file.\n");
        return DECRYPT_ERROR; 
    }

    /* find end of file for length */
    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    aSize = length;

    input = malloc(aSize);
    output = malloc(aSize);

    InitRng(&rng);

    /* reads from inFile and wrties whatever is there to the input array */
    ret = fread(input, 1, length, inFile);
    if (ret != length) {
        printf("Input file does not exist.\n");
        return FREAD_ERROR;
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
        return ret;

	/* change length to remove salt/iv block from being decrypted */
    length -= (block + SALT_SIZE);
    for (i = 0; i < length; i++) {
        /* shifts message: ignores salt/iv on message*/
        input[i] = input[i + (block + SALT_SIZE)];
    }
    /* sets key decrypts the message to ouput from input length */
#ifndef NO_AES
    if (strcmp(alg, "aes") == 0) {
        if (strcmp(mode, "cbc") == 0) {
		    ret = AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
	        if (ret != 0)
	            return ret;
	        ret = AesCbcDecrypt(&aes, output, input, length);
	        if (ret != 0)
	            return DECRYPT_ERROR;
        }
#ifdef CYASSL_AES_COUNTER
        else if (strcmp(mode, "ctr") == 0) {
            /* if mode is ctr */
            AesSetKeyDirect(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
            AesCtrEncrypt(&aes, output, input, length);
        }
#endif
}
#endif
#ifndef NO_DES3
	if (strcmp(alg, "3des") == 0) {
		ret = Des3_SetKey(&des3, key, iv, DES_DECRYPTION);
	    if (ret != 0)
	        return ret;
	    ret = Des3_CbcDecrypt(&des3, output, input, length);
	    if (ret != 0)
	        return DECRYPT_ERROR;
	}
#endif
#ifdef HAVE_CAMELLIA
	if (strcmp(alg, "camellia") == 0) {
	    ret = CamelliaSetKey(&camellia, key, block, iv);
	    if (ret != 0)
	        return ret;
	    CamelliaCbcDecrypt(&camellia, output, input, length);
	}
#endif

    if (salt[0] != 0) {
        /* reduces length based on number of padded elements  */
        length -= output[length-1];
    }
    /* writes output to the outFile based on shortened length */
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory */
    memset(input, 0, aSize);
    memset(output, 0, aSize);
    memset(key, 0, size);
    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);

    return 0;
}

/*
 * benchmarking funciton 
 */
int Benchmark(int timer, int* option)
{
#ifndef NO_AES
    Aes aes;                /* aes declaration */
#endif

#ifndef NO_DES3
	Des3 des3;              /* 3des declaration */
#endif

    RNG rng;                /* random number generator */

    int             ret = 0;/* return variable */
    double          start;  /* start time */
    ALIGN16 byte*   plain;  /* plain text */
    ALIGN16 byte*   cipher; /* cipher */
    ALIGN16 byte*   key;    /* key for testing */
    ALIGN16 byte*   iv;     /* iv for initial encoding */
    byte*           digest; /* message digest */

    InitRng(&rng);

    signal(SIGALRM, Stopf);
#ifndef NO_AES
    /* aes test */
    if (option[i] == 1) {
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
        printf("AES-CBC ");
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
    }
    i++;
#endif
#ifdef CYASSL_AES_COUNTER
    /* aes-ctr test */
    if (option[i] == 1) {
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
                       
        AesSetKeyDirect(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        while (loop) {
            AesCtrEncrypt(&aes, cipher, plain, AES_BLOCK_SIZE);
            blocks++;
        }
        printf("AES-CTR ");
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
    }
    i++;
#endif
#ifndef NO_DES3
    /* 3des test */
    if (option[i] == 1) {   
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
    }
    i++;
#endif
#ifdef HAVE_CAMELLIA
    /* camellia test */
    if (option[i] == 1) {
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
    }
    i++;
#endif

#ifndef NO_MD5
    /* md5 test */
    if (option[i] == 1) {
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
    }
    i++;
#endif

#ifndef NO_SHA
    /* sha test */
    if (option[i] == 1) {
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
    }
    i++;
#endif

#ifndef NO_SHA256
    /* sha256 test */
    if (option[i] == 1) {
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
    }
    i++;
#endif

#ifdef CYASSL_SHA384
    /* sha384 test */
    if (option[i] == 1) {
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
    }
    i++;
#endif

#ifdef CYASSL_SHA512
    /* sha512 test */
    if (option[i] == 1) {
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
    }
    i++;
#endif

#ifdef HAVE_BLAKE2
    /* blake2b test */
    if (option[i] == 1) {
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
    }
#endif
    return ret;
}

/*
 * hashing function 
 */
int Hash(char* in, char* len, char* out, char* alg, int size)
{
#ifdef HAVE_BLAKE2
    Blake2b hash;               /* blake2b declaration */
#endif
    FILE*   inFile;              /* input file */
    FILE*   outFile;             /* output file */

    byte*   input;              /* input buffer */
    byte*   output;             /* output buffer */

    int     ret;                /* return variable */
    int     length;             /* length of hash */

    output = malloc(size);
    memset(output, 0, size);

    /* opens input file */
    inFile = fopen(in, "r");
    if (inFile == NULL) {
        /* if no input file was provided */
        if (len != NULL)
            /* if length was provided */
            length = atoi(len);
        else
            length = strlen(in);

        input = malloc(length);
        for (i = 0; i < length; i++) {
            /* copies text from in to input */
             if (i <= strlen(in))
                input[i] = in[i];
        }
    }
    else {
        /* if input file provided finds end of file for length */
        fseek(inFile, 0, SEEK_END);
        int leng = ftell(inFile);
        fseek(inFile, 0, SEEK_SET);

        if (len != NULL) {
            /* if length is provided */
            length = atoi(len);
            input = malloc(length);
        }
        else 
            length = leng;
        
        input = malloc(length);
        if (input == NULL) {
            printf("Failed to create input buffer\n");
            return FATAL_ERROR;
        }
        ret = fread(input, 1, leng, inFile);
        fclose(inFile);
    }

    /* hashes using accepted algorithm */
#ifndef NO_MD5    
    if (strcmp(alg, "-md5") == 0) {
        ret = Md5Hash(input, length, output);
    }
#endif
#ifndef NO_SHA  
    else if (strcmp(alg, "-sha") == 0) {
        ret = ShaHash(input, length, output);
    }
#endif
#ifndef NO_SHA256  
    else if (strcmp(alg, "-sha256") == 0) {
        ret = Sha256Hash(input, length, output);
    }
#endif
#ifdef CYASSL_SHA384
    else if (strcmp(alg, "-sha384") == 0) {
        ret = Sha384Hash(input, length, output);
    }
#endif
#ifdef CYASSL_SHA512
    else if (strcmp(alg, "-sha512") == 0) {
        ret = Sha512Hash(input, length, output);
    }
#endif
#ifdef HAVE_BLAKE2
    else if (strcmp(alg, "-blake2b") == 0) { 
        ret = InitBlake2b(&hash, size);
        ret = Blake2bUpdate(&hash, input, length);
        ret = Blake2bFinal(&hash, output, size);
    }
#endif
    if (ret == 0) {
        /* if no errors so far */
        if (out != NULL) {
            /* if output file provided */
            outFile = fopen(out, "w");
            if (outFile != NULL) {
                /* if outFile exists */
                for (i = 0; i < size; i++) {
                    /* writes hashed output to outFile */
                    fprintf(outFile, "%02x", output[i]);
                }
                fclose(outFile);
            }
        }
        else {
            /*  if no output file*/
            for (i = 0; i < size; i++) {
                /* write hashed output to terminal */
                printf("%02x", output[i]);
            }
            printf("\n");
        }
    }

    /* closes the opened files and frees the memory */
    memset(input, 0, length);
    memset(output, 0, size);
    free(input);
    free(output);
    return ret;
}

