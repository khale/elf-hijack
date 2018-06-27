CFLAGS=-m32
CC=gcc

all: parasite hijack target

parasite:  parasite.c
	$(CC) $(CFLAGS) -fPIC -c $< -nostdlib -o libtest.o
	ld -melf_i386 -shared -o libtest.so.1.0 libtest.o

target: target.c
	$(CC) $(CFLAGS) $< -o $@

hijack: hijack.c
	$(CC) $(CFLAGS) $< -o $@

clean: 
	rm -f hijack libtest.so.1.0 libtest.o target
