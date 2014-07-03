CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

all: encrypt decrypt hash

encrypt: util.o encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

decrypt: util.o decrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

hash: util.o hash.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	find . \! -name util.c \! -name Makefile \! -name README.md \! -name util.h \! -name encrypt.c \! -name decrypt.c \! -name hash.c -delete
