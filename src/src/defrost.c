#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include "process.h"

void syscall_check(int retval, int can_be_fake, char* desc, ...) {
	va_list va_args;
	/* can_be_fake is true if the syscall might return -1 anyway, and
	 * we should simply check errno.
	 */
	if (can_be_fake && errno == 0) return;
	if (retval == -1) {
		char str[1024];
		snprintf(str, 1024, "Error in %s: %s\n", desc, strerror(errno));
		vfprintf(stderr, str, va_args);
		exit(1);
	}
}

void safe_read(int fd, void* dest, size_t count, char* desc) {
    int ret;
	ret = read(fd, dest, count);
    if (ret == -1) {
        fprintf(stderr, "Read error on %s: %s\n", desc, strerror(errno));
        exit(1);
    }
    if (ret < count) {
        fprintf(stderr, "Short read on %s\n", desc);
        exit(1);
	}
}

int resume_image_from_file(char* fn) {
    int num_maps;
    int fd;
    struct map_entry_t map;
    pid_t pid;
    struct user user_data;
    struct user_i387_struct i387_data;
    sigset_t zeromask;
    long* ptr;
    int i;

    sigemptyset(&zeromask);

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Couldn't open file: %s\n", strerror(errno));
		exit(1);
	}

	safe_read(fd, &user_data, sizeof(struct user), "user data");
	safe_read(fd, &i387_data, sizeof(struct user_i387_struct), "i387 data");
	safe_read(fd, &num_maps, sizeof(int), "num_maps");

	while(num_maps--) {
		safe_read(fd, &map, sizeof(struct map_entry_t), "a map");
		syscall_check( (int)
			mmap((void*)map.start, map.length, map.prot, MAP_ANONYMOUS|MAP_FIXED|map.flags,
                -1, 0), 0,
			"mmap(0x%lx, 0x%lx, %x, %x, -1, 0)",
                map.start, map.length, map.prot, map.flags);

		if (map.data != NULL)
			safe_read(fd, (void*)map.start, map.length, "map data");
	}

    close(fd);

	/* now fork a child to ptrace us */
	switch (pid = fork()) {
		case -1:
			fprintf(stderr, "fork() failed: %s\n", strerror(errno));
			exit(1);
		case 0: /* am child */
            sleep(1);

            fprintf(stderr, "Argh! Fell through. Dammit.\n");
            exit(1);
            /* should never be hit */
        default: /* parent */
			syscall_check(
                    ptrace(PTRACE_ATTACH, pid, 0, 0), 1,
                    "ptrace(PTRACE_ATTACH)");
            syscall_check(waitpid(pid, &i, 0), 0, "wait(child)");
            /* parent should be stopped so we do not need to wait() */
            ptr = (long*)&user_data;
            i = sizeof(user_data);
            for(i=0; i < sizeof(user_data); i+=4, ptr++) {
                ptrace(PTRACE_POKEUSER, pid, i, *ptr);
            }
            /* let it loose! */
            syscall_check(
                    ptrace(PTRACE_DETACH, pid, 0, 0), 0,
                    "ptrace(PTRACE_DETACH, %d, 0, 0)", pid, 0, 0);
            syscall_check(waitpid(pid, &i, 0), 0, "wait(child)");
            /* Do onto one's self what was done unto one's child */
            if (WIFSIGNALED(i)) {
                raise(WSTOPSIG(i));
            }
            if (WIFEXITED(i)) {
                _exit(i);
            }
	}
    return 1;
}

void* get_task_size() {
    /* stolen from isec brk exploit :) */
    unsigned tmp;
    return (void*)(((unsigned)&tmp + (1024*1024*1024)) / (1024*1024*1024) * (1024*1024*1024));
}

int real_main(int argc, char** argv) {
	pid_t target_pid;
    /* Parse options */
    while (1) {
        int option_index = 0;
        int c;
        static struct option long_options[] = {
            {0, 0, 0, 0},
        };
        
        c = getopt_long(argc, argv, "",
                long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
            case '?':
                /* invalid option */
                exit(1);
                break;
        }
    }

	if (argc - optind != 1) {
		printf("Usage: %s [options] <filename>\n", argv[0]);
		return 1;
	}

    resume_image_from_file(argv[optind]);

	fprintf(stderr, "Something went wrong :(\n");
	return 1;
}

int real_argc;
char** real_argv;
char** new_environ;
extern char** environ;

int main(int argc, char**argv) {
    long amount_used;
    void *stack_ptr;
    void *top_of_old_stack, *bottom_of_old_stack;
    void *top_of_new_stack;
    long size_of_new_stack;
    
    int i;

    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    /* save these things: */
    real_argc = argc;
    real_argv = malloc(sizeof(char*)*argc);
    for(i=0; i < argc; i++)
        real_argv[i] = strdup(argv[i]);
    real_argv[i] = NULL;

    new_environ = environ;
    for(i = 0; environ[i]; i++); /* count environment variables */
    new_environ = malloc(sizeof(char*)*i);
    for(i = 0; environ[i]; i++)
        *new_environ++ = strdup(environ[i]);
    *new_environ = NULL;
    environ = new_environ;

    top_of_old_stack = get_task_size();
    stack_ptr = &stack_ptr;

    amount_used = top_of_old_stack - stack_ptr;

    top_of_new_stack = (void*)0x02000000;
    size_of_new_stack = 8192;

    syscall_check( (int)
        mmap(top_of_new_stack - size_of_new_stack, size_of_new_stack,
            PROT_READ|PROT_WRITE|PROT_EXEC,
            MAP_ANONYMOUS|MAP_FIXED|MAP_GROWSDOWN|MAP_PRIVATE, -1, 0),
        0, "mmap(newstack)");
    memset(top_of_new_stack - size_of_new_stack, 0, size_of_new_stack);
    memcpy(top_of_new_stack - size_of_new_stack,
            top_of_old_stack - size_of_new_stack, /* FIX ME */
            size_of_new_stack);
    bottom_of_old_stack = (void*)(((unsigned long)sbrk(0) + PAGE_SIZE - 1) & PAGE_MASK);
    __asm__ ("addl %0, %%esp" : : "a"(top_of_new_stack - top_of_old_stack));

    /* unmap absolutely everything above us! */
    syscall_check(
            munmap(top_of_new_stack,
                (top_of_old_stack - top_of_new_stack)),
                0, "munmap(stack)");
    
    return real_main(real_argc, real_argv);
}

