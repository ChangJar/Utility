CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

all: encrypt decrypt hash benchmark cyassl

encrypt: util.o encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

decrypt: util.o decrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

hash: util.o hash.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

benchmark: util.o benchmark.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

cyassl: util.o cyassl.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	find . \! -name util.c \! -name Makefile \! -name README.md \! -name util.h \! -name encrypt.c \! -name decrypt.c \! -name hash.c \! -name benchmark.c \! -name cyassl.c -delete
