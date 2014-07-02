CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

encrypt: util.o encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

.PHONY: clean

clean:
	find . \! -name util.c \! -name Makefile \! -name README.md \! -name util.h \! -name encrypt.c -delete
