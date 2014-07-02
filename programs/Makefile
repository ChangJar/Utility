CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

encrypt: enc.o encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

.PHONY: clean

clean:
	find . \! -name enc.c \! -name Makefile \! -name README.md \! -name enc.h \! -name encrypt.c -delete
