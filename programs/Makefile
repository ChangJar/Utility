CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

cyassl: util.o cyassl.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o cyassl
