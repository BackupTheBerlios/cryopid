;
; Process resumer.
;   (C) 2004 Bernard Blackham <bernard@blackham.com.au>
;
; Licensed under a BSD-ish license.
;
; Exit codes:
;  10: Could not open file.
;  23: Process never resumed.
;

BITS 32
    org     0x00100000
ehdr:                                                 ; Elf32_Ehdr
              db      0x7F, "ELF", 1, 1, 1            ;   e_ident
      times 9 db      0
              dw      2                               ;   e_type
              dw      3                               ;   e_machine
              dd      1                               ;   e_version
              dd      _start                          ;   e_entry
              dd      phdr - $$                       ;   e_phoff
              dd      0                               ;   e_shoff
              dd      0                               ;   e_flags
              dw      ehdrsize                        ;   e_ehsize
              dw      phdrsize                        ;   e_phentsize
              dw      1                               ;   e_phnum
              dw      0                               ;   e_shentsize
              dw      0                               ;   e_shnum
              dw      0                               ;   e_shstrndx

ehdrsize      equ     $ - ehdr

phdr:                                                 ; Elf32_Phdr
              dd      1                               ;   p_type
              dd      0                               ;   p_offset
              dd      $$                              ;   p_vaddr
              dd      $$                              ;   p_paddr
              dd      filesize                        ;   p_filesz
              dd      0x4000                          ;   p_memsz
              dd      7                               ;   p_flags
              dd      0x1000                          ;   p_align


phdrsize      equ     $ - phdr

_start:
	; get rid of argc & argv[0]
	pop eax
	pop eax

	; open(argv[1], for reading, no mode)
	mov eax, 5
	pop ebx   ; argv[1] on stack
	mov ecx, 0
	mov edx, 0
	int 0x80

	; ASSUME THE FILE HANDLE WILL ALWAYS BE 3

    ; (unless it failed of course)
    cmp eax, 0
    jge open_good
    ; else exit(10)
    mov eax, 1
    mov ebx, 10
    int 0x80
	
open_good:
	; Read in user data for parent
	mov eax, 3
	mov ebx, 3
	mov ecx, dataorg
	mov edx, 284 + 108 ; 284 bytes of user data, 108 of FP regs
	int 0x80

	; fork!
	mov eax, 2
	int 0x80

	; test for parent/child
	or eax, eax
	jnz parent
    jmp child

parent:
	; am parent.
	push eax ; pid onto stack
	
	; close file handle
	mov eax, 6
	mov ebx, 3
	int 0x80

	; wait for child
    push 0
	mov eax, 7
	mov ebx, -1 ; for any child. we only have one.
	mov ecx, esp ; don't care about status
	mov edx, 0 ; no options
	int 0x80
    pop eax

	mov eax, 284 - 4; sizeof(user)

keep_on_poking:
	push eax ; push location onto stack
	; ptrace POKEUSER
	mov esi, [dataorg+eax]
	mov eax, 26
	mov ebx, 6 ; POKEUSER
	mov ecx,[esp+4] ; pid off stack

	mov edx,[esp] ; location from stack

	int 0x80
    ; This is likely to fail in some cases (poking kernel data)
    ; so ignore the result.
	
poke_good:
	pop eax
	sub eax, 4
	jnc keep_on_poking
    ; poke FP regs
    mov eax, 26
    mov ebx, 15 ; SETFPREGS
    mov ecx, [esp]
    mov edx, 0
    mov esi, dataorg+284 ; offset sizeof(struct user) bytes, into user_i387_struct
    int 0x80

    ; Let it loose!

	; ptrace DETACH
	mov eax, 26
	mov ebx, 17 ; DETACH
	mov ecx, [esp] ; pid off stack
	mov edx, 0
	mov esi, 0
	int 0x80

    ; wait on child
keep_on_waiting:
	mov eax, 7
	mov ebx, -1 ; for any child. we only have one.
	mov ecx, dataorg ; don't care about status
	mov edx, 0 ; no options
	int 0x80
    cmp eax, 0
    jnl keep_on_waiting

    pop esi

	; exit(0)
    mov ebx, [dataorg]
    shr ebx, 8
	mov eax, 1
	int 0x80

child:
	; am child.
    ; move stack into top of dataorg
    mov esp, dataorg+0x1e00

	; munmap old stack
	mov eax, 91
	mov ebx, 0xbfffe000
	mov ecx, 0x2000
	int 0x80


	; read num maps (4 bytes) into dataorg
	mov eax, 3
	mov ebx, 3
	mov ecx, dataorg
	mov edx, 4  ; 4 byte integer
	int 0x80

map_loop:
	; for each map:
	mov eax, [dataorg]
	or eax, eax
	jnz keep_reading_maps

; end of map_loop :

	; ptrace(PTRACE_TRACEME)
	mov eax, 26
	mov ebx, 0
	mov ecx, 0
	mov edx, 0
	mov esi, 0
	int 0x80

	; munmap data segment of this (no longer needed)
	mov eax, 91
	mov ebx, 0x101000
	mov ecx, 0xc000
	int 0x80

    ; getpid && kill(me, SIGSTOP)
    mov eax, 20 ; getpid
    int 0x80
    mov ebx, eax
    mov eax, 37  ; kill
    mov ecx, 19  ; SIGSTOP
    int 0x80

    ; exit(23)
    mov eax, 1
    mov ebx, 23
    int 0x80

keep_reading_maps:
	dec eax
	mov [dataorg], eax

	; read map_entry_t structure into dataorg+4
	mov eax, 3
	mov ebx, 3
	mov ecx, dataorg+4
	mov edx, 1056 ; sizeof map_entry_t
	int 0x80

	; if it is a file mapping
	mov eax, [dataorg+4+(4*7)]
	or eax, eax
	jz anonymous_map

	; open that file. put the fd on the stack.
	mov eax, 5
	mov ebx, dataorg+4+(4*7) ; filename in map_entry_t
	mov ecx, 0 ; XXX FIXME ... get the damn mode flags right.
	mov edx, 0
	int 0x80

	push eax ; fd in eax onto stack
	jmp mmap_continue

anonymous_map:
	; no fd, put null on stack.
	mov eax, -1
	push eax

mmap_continue: 
	; we call the mmap function. as mmap takes 6 arguments, we need
	; to put them in memory somewhere. Hey look, the layout of
	; struct map_entry_t is exactly like what we want for mmap
	; except we blat over dev, with fd. cool :))
	mov eax,[esp]
	mov [dataorg + 4 + (4*4)], eax
	mov eax, 90 ; old_mmap
	mov ebx, dataorg + 4
	int 0x80
	; yay?

	; if there is data to put in it too...
	mov eax, [dataorg+4+(1052)]
	or eax, eax
	jnz write_mmap_data ; restart loop

    ; close file
    mov eax, 6 ; close
    pop ebx
    int 0x80
    jmp map_loop

write_mmap_data:
    pop ebx ; spurious fh
	; but if it is an anonymous mapping, we have stuff to put in there.
	; read map_entry_t structure into start location
	mov eax, 3  ; read
	mov ebx, 3
	mov ecx, [dataorg+4] ; m->start
	mov edx, [dataorg+8] ; m->length
	int 0x80

	jmp map_loop

timespec db 2, 0
filesize	equ     $ - $$
dataorg		equ	$$ + ((filesize + 16) & ~15)
