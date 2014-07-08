CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

cyassl: util.o cyassl.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o cyassl
