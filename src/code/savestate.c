/*
 * Process state saver
 *   (C) 2004 Bernard Blackham <bernard@blackham.com.au>
 *
 * Licensed under a BSD-ish license.
 */


#include <sys/types.h>
#include <linux/user.h>
#include <sys/ptrace.h>
#include "process.h"

#ifdef SHOW_SIZES
int main(int argc, char** argv) {
    printf("sizeof(map_entry_t): %d\n", sizeof(struct map_entry_t));
    printf("sizeof(proc_image_t): %d\n", sizeof(struct proc_image_t));
    printf("sizeof(user): %d\n", sizeof(struct user));
    printf("sizeof(user_i387_struct): %d\n", sizeof(struct user_i387_struct));
    printf("PTRACE_TRACEME: %d\n", PTRACE_TRACEME);
    printf("PTRACE_PEEKUSER: %d\n", PTRACE_PEEKUSER);
    printf("PTRACE_PEEKDATA: %d\n", PTRACE_PEEKDATA);
    printf("PTRACE_GETREGS: %d\n", PTRACE_GETREGS);
    printf("PTRACE_POKEUSER: %d\n", PTRACE_POKEUSER);
    printf("PTRACE_SETFPREGS: %d\n", PTRACE_SETFPREGS);
    printf("PTRACE_DETACH: %d\n", PTRACE_DETACH);
    printf("PTRACE_CONT: %d\n", PTRACE_CONT);
    printf("PTRACE_SINGLESTEP: %d\n", PTRACE_SINGLESTEP);
    return 0;
}
#else
int main(int argc, char** argv) {
	pid_t target_pid;
	struct proc_image_t* proc_image;
    int c;
    int flags = 0;
    
    /* Parse options */
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"full-image", 0, 0, 'f'},
            {"stopped", 0, 0, 's'},
            {0, 0, 0, 0},
        };
        
        c = getopt_long(argc, argv, "fs",
                long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
            case 'f':
                flags |= GET_PROC_FULL_IMAGE;
                break;
            case 's':
                flags |= GET_PROC_IS_STOPPED;
                break;
            case '?':
                /* invalid option */
                exit(1);
                break;
        }
    }

	if (argc - optind != 2) {
		printf("Usage: %s [options] <pid> <filename>\n", argv[0]);
		return 1;
	}

	target_pid = atoi(argv[optind]);
	if (target_pid <= 1) {
		printf("Invalid pid: %d\n", target_pid);
		return 1;
	}

	proc_image = get_proc_image(target_pid, flags);

    write_proc_image_to_file(proc_image, argv[optind+1]);

	return 0;
}
#endif
