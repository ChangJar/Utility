CC=gcc
CFLAGS=-Wall
LIBS=-lcyassl

exc: enc.o encrypt.o
	$(CC) -o encrypt encrypt.o enc.o

encrypt: encrypt.o
	$(CC) -c $@ $^ $(CFLAGS) $(LIBS)

enc: enc.o
	$(CC) -c $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f encrypt *.o
