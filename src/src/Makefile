CFLAGS = -g
DEPAX = chpax -xperms
#DEPAX = true
all: defrost

clean:
	rm -f *.o defrost

defrost: process.o defrost.o
	#$(LD) -o $@ $^ -static -Tmylinking.ld --eh-frame-hdr -m elf_i386 \
	#               -dynamic-linker \
	#               /lib/ld-linux.so.2 \
	#               /usr/lib/crt1.o \
	#               /usr/lib/crti.o \
	#               /usr/lib/gcc-lib/i486-linux/3.3.3/crtbegin.o \
	#               -L/usr/lib/gcc-lib/i486-linux/3.3.3 \
	#               -L/usr/lib/gcc-lib/i486-linux/3.3.3 \
	#               /usr/lib/gcc-lib/i486-linux/3.3.3/crtend.o \
	#               /usr/lib/crtn.o \
	#               -lc -lgcc
	gcc -static -o $@ -Tmylinking.ld $^
	$(DEPAX) $@
