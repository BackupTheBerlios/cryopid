CFLAGS=-g -Wall

OBJECTS = test easytest savestate resume sizes

DEPAX = chpax -xperms 

all: $(OBJECTS)

clean:
	rm -f *.o $(OBJECTS)

easytest: easytest.c
	$(CC) $(CFLAGS) -o $@ $< 
	$(DEPAX) $@

test: test.c
	$(CC) $(CFLAGS) -o $@ $^
	$(DEPAX) $@

savestate: savestate.c process.o
	$(CC) $(CFLAGS) -o $@ $^
	$(DEPAX) $@

sizes: savestate.c process.o
	$(CC) $(CFLAGS) -DSHOW_SIZES -o $@ $< 
	$(DEPAX) $@

resume: resume.asm
	nasm -o $@  $<
	$(DEPAX) $@
	chmod 755 $@
