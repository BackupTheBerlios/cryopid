/*
 * Process state saver
 *   (C) 2004 Bernard Blackham <bernard@blackham.com.au>
 *
 * Licensed under a BSD-ish license.
 */
#include <malloc.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <signal.h>
#include <linux/user.h>
#include <linux/kdev_t.h>
#include "process.h"

#define RESUME_ORG 0x00100000

int write_proc_image_to_file(struct proc_image_t* p, char* fn) {
    FILE* f;
    int i;

    if (!(f = fopen(fn, "w"))) {
        perror("fopen():");
        return 0;
    }

    fwrite(&p->user_data, sizeof(p->user_data), 1, f);
    fwrite(&p->i387_data, sizeof(p->i387_data), 1, f);
    fwrite(&p->num_maps, sizeof(p->num_maps), 1, f);
    for (i = 0; i < p->num_maps; i++) {
        fwrite(&p->maps[i], sizeof(p->maps[i]), 1, f);
        if (p->maps[i].data)
            fwrite(p->maps[i].data, p->maps[i].length, 1, f);
    }

    fclose(f);
    return 1;
}

void start_ptrace(pid_t target_pid, int is_stopped) {
	long ret;
	int status;

	ret = ptrace(PTRACE_ATTACH, target_pid, 0, 0);
	if (ret == -1) {
		perror("Failed to ptrace");
		exit(1);
	}

    if (is_stopped) return; /* don't bother waiting for it, we'll just hang */

	ret = waitpid(target_pid, &status, 0);
	if (ret == -1) {
		perror("Failed to wait for child");
		exit(1);
	}
	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "Failed to get child stopped.\n");
	}
}

void end_ptrace(pid_t target_pid) {
	long ret;

	ret = ptrace(PTRACE_DETACH, target_pid, 0, 0);
	if (ret == -1) {
		perror("Failed to detach ptrace");
		exit(1);
	}
}

int parse_map_line(pid_t target_pid, char* map_line, struct map_entry_t* m, int get_library_data) {
	/* Precondition: target_pid must be ptrace_attached */
	char *ptr1, *ptr2;
    int dminor, dmajor;

	memset(m, 0, sizeof(struct map_entry_t));

	/* Parse a line that looks like one of the following: 
	    08048000-080ab000 r-xp 00000000 03:03 1309106    /home/b/dev/sp/test
	    080ab000-080ae000 rw-p 00062000 03:03 1309106    /home/b/dev/sp/test
	    080ae000-080db000 rwxp 00000000 00:00 0 
	    40000000-40203000 rw-p 00000000 00:00 0 
	    bfffe000-c0000000 rwxp 00000000 00:00 0 
	*/

	ptr1 = map_line;
	if ((ptr2 = strchr(ptr1, '-')) == NULL) {
		fprintf(stderr, "No - in map line!\n");
		return 0;
	}
	*ptr2 = '\0';
	m->start = strtoul(ptr1, NULL, 16);

	ptr1 = ptr2+1;
	if ((ptr2 = strchr(ptr1, ' ')) == NULL) {
		fprintf(stderr, "No end of end in map line!\n");
		return 0;
	}
	*ptr2 = '\0';
	m->length = strtoul(ptr1, NULL, 16) - m->start;

	m->prot = 0;
	ptr1 = ptr2+1;

	if (ptr1[0] == 'r')
		m->prot |= PROT_READ;
	else if (ptr1[0] != '-')
		fprintf(stderr, "Bad read flag: %c\n", ptr1[0]);

	if (ptr1[1] == 'w')
		m->prot |= PROT_WRITE;
	else if (ptr1[1] != '-')
		fprintf(stderr, "Bad write flag: %c\n", ptr1[1]);

	if (ptr1[2] == 'x')
		m->prot |= PROT_EXEC;
	else if (ptr1[2] != '-')
		fprintf(stderr, "Bad exec flag: %c\n", ptr1[2]);

    m->flags = MAP_FIXED;
	if (ptr1[3] == 's')
        m->flags |= MAP_SHARED;
	else if (ptr1[3] != 'p')
		fprintf(stderr, "Bad shared flag: %c\n", ptr1[3]);
    else
        m->flags |= MAP_PRIVATE;

	ptr1 = ptr1+5; /* to pgoff */
	if ((ptr2 = strchr(ptr1, ' ')) == NULL) {
		fprintf(stderr, "No end of pgoff in map line!\n");
		return 0;
	}
	*ptr2 = '\0';
	m->pg_off = strtoul(ptr1, NULL, 16);

    if ((signed long)m->pg_off < 0) {
        m->flags |= MAP_GROWSDOWN;
    }

	ptr1 = ptr2+1;
	if ((ptr2 = strchr(ptr1, ':')) == NULL) {
		fprintf(stderr, "No end of major dev in map line!\n");
		return 0;
	}
	*ptr2 = '\0';
	dmajor = strtoul(ptr1, NULL, 16);

	ptr1 = ptr2+1;
	if ((ptr2 = strchr(ptr1, ' ')) == NULL) {
		fprintf(stderr, "No end of minor dev in map line!\n");
		return 0;
	}
	*ptr2 = '\0';
	dminor = strtoul(ptr1, NULL, 16);
    
    m->dev = MKDEV(dmajor, dminor);

	ptr1 = ptr2+1;
	if ((ptr2 = strchr(ptr1, ' ')) != NULL) {
        *ptr2 = '\0';
        m->inode = strtoul(ptr1, NULL, 10);

        ptr1 = ptr2+1;
        while (*ptr1 == ' ') ptr1++;
        if (*ptr1 != '\n') { /* we have a filename too to grab */
            ptr2 = strchr(ptr1, '\n');
            if (ptr2) *ptr2 = '\0';
            strcpy(m->filename,ptr1);
        } else {
            m->flags |= MAP_ANONYMOUS;
        }
    } else {
        m->inode = strtoul(ptr1, NULL, 10);
    }

    /* we have all the info we need, regurgitate it for confirmation */
    fprintf(stderr, "Map: %08lx-%08lx %c%c%c%c %08lx %02x:%02x %-10ld %s\n",
            m->start, m->start + m->length,
            (m->prot & PROT_READ)?'r':'-',
            (m->prot & PROT_WRITE)?'w':'-',
            (m->prot & PROT_EXEC)?'x':'-',
            (m->flags & MAP_SHARED)?'s':'p',
            m->pg_off,
            MAJOR(m->dev), MINOR(m->dev),
            m->inode,
            m->filename);

    if (get_library_data) {
        /* forget the fact it came from a file. Pretend it was just
         * some arbitrary anonymous writeable VMA.
         */
        memset(m->filename, 0, sizeof(m->filename));
        m->inode = 0;
        m->prot |= PROT_WRITE;

        m->flags &= ~MAP_SHARED;
        m->flags |= MAP_PRIVATE;
        m->flags |= MAP_ANONYMOUS;
    }

	/* Now to get data too */
	if (((m->prot & PROT_WRITE) && (m->flags & MAP_PRIVATE))) {
            // || (m->prot & MAP_ANONYMOUS)) {
		/* We have a memory segment. We should retrieve it's data */
		long *pos, *end;
        long *datapos;
		/*fprintf(stderr, "Retrieving %ld bytes from segment 0x%lx... ",
				m->length, m->start); */
		m->data = malloc(m->length);
        datapos = m->data;
        end = (long*)(m->start + m->length);

		for(pos = (long*)m->start; pos < end; pos++, datapos++) {
            *datapos = 
				ptrace(PTRACE_PEEKDATA, target_pid, pos, datapos);
			if (errno != 0) perror("ptrace(PTRACE_PEEKDATA)");
		}

		/*fprintf(stderr, "done.\n"); */
        m->pg_off = 0;
	} else {
        m->data = NULL;
    }

	return 1;
}

int get_user_data(pid_t target_pid, struct user *user_data) {
	long pos;
	int* user_data_ptr = (int*)user_data;

	/* We have a memory segment. We should retrieve it's data */
	for(pos = 0; pos < sizeof(struct user)/sizeof(int); pos++) {
		user_data_ptr[pos] =
			ptrace(PTRACE_PEEKUSER, target_pid, (void*)(pos*4), NULL);
		if (errno != 0) {
			perror("ptrace(PTRACE_PEEKDATA): ");
		}
	}

	return 1;
}

int get_i387_data(pid_t target_pid, struct user_i387_struct* i387_data) {
	/* We have a memory segment. We should retrieve it's data */
	fprintf(stderr, "Retrieving FP registers... ");

    if (ptrace(PTRACE_GETFPREGS, target_pid, 0, i387_data) == -1) {
        perror("ptrace(PTRACE_PEEKDATA): ");
        return 0;
    }

	fprintf(stderr, "Done.\n");
	return 1;
}

struct proc_image_t* get_proc_image(pid_t target_pid, int flags) {
	FILE *mapf;
	char maps_fn[1024];
	char map_line[1024];
	struct proc_image_t *proc_image;
	int map_count = 0;

	proc_image = malloc(sizeof(struct proc_image_t));

	/* FIXME being liberal here: */
	proc_image->maps = malloc(sizeof(struct map_entry_t)*1000);

    //if (kill(target_pid, SIGSTOP) == -1) perror("kill");
	start_ptrace(target_pid, flags & GET_PROC_IS_STOPPED);
	snprintf(maps_fn, 1024, "/proc/%d/maps", target_pid);
	mapf = fopen(maps_fn, "r");
	while (fgets(map_line, 1024, mapf)) {
		if (!parse_map_line(target_pid, map_line, &(proc_image->maps[map_count]), flags & GET_PROC_FULL_IMAGE))
			fprintf(stderr, "Error parsing map: %s", map_line);
		else
            if (proc_image->maps[map_count].start == RESUME_ORG)
                fprintf(stderr, "Ignoring map - looks like resumer.\n");
            else
                map_count++;
	}
	fclose(mapf);
	proc_image->num_maps = map_count;
	fprintf(stderr, "Read %d maps\n", map_count);

	/* Get process's user data (includes gen regs) */
	if (!get_user_data(target_pid, &(proc_image->user_data))) {
		fprintf(stderr, "Error getting user data.\n");
		return NULL;
	}

	/* Get FP regs */
	if (!get_i387_data(target_pid, &(proc_image->i387_data))) {
		fprintf(stderr, "Error getting user data.\n");
		return NULL;
	}

	end_ptrace(target_pid);
	return proc_image;
}

