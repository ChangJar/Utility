CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

cyassl: util.o cyassl.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	find . \! -name Makefile \! -name cyassl.c \! -name util.c \! -name util.h \! -name README.md -delete
