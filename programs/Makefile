CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

cyassl: util.o cyassl.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	find . \! -name util.c \! -name Makefile \! -name README.md \! -name util.h  \! -name cyassl.c -delete
