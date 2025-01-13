#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <elf.h>
#include <assert.h>
#include <sys/wait.h>
#include <signal.h>
#include <libgen.h>
#include <sys/reg.h>

#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFFFFFFFFFF00

struct handler{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    char *mem;
    char *exec;
    char *symname;
    Elf64_Addr symaddr;
    
};

static int lookup_symbol(struct handler *trace_hander);

void run_and_watch_breakpoint(const struct handler *trace_handler, pid_t child_pid);

int main(int argc, char* argv[])
{
    int fd;
    struct handler trace_handler;
    
    if (argc != 3)
    {
        printf("Usage: %d <exec> <funcname>\n", argv[0]);
        return -1;
    }

    memset(&trace_handler, 0, sizeof(trace_handler));
    trace_handler.exec = argv[1];
    trace_handler.symname = argv[2];
    //open elf file.
    fd = open(trace_handler.exec, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }

    struct stat file_stat;
    //get file size.
    if (fstat(fd, &file_stat) < 0)
    {
        perror("fstat");
        return -1;
    }
    //mmap elf file into memory.
    trace_handler.mem = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (trace_handler.mem == MAP_FAILED)
    {
        perror("mmap");
        return -1;
    }

    /**
     * Elf header at offset 0.
     * we should judge elf magic first.
    */
    if (trace_handler.mem[0] != 0x7f || strncmp(&trace_handler.mem[1], "ELF", 3))
    {
        printf("ELF magic check failed.\n");
        return -1;
    }

    trace_handler.ehdr = (Elf64_Ehdr *)trace_handler.mem;
    trace_handler.shdr = (Elf64_Shdr *)&trace_handler.mem[trace_handler.ehdr->e_shoff];
    trace_handler.phdr = (Elf64_Phdr *)&trace_handler.mem[trace_handler.ehdr->e_phoff];

    //we only parse executable 
    if (trace_handler.ehdr->e_type != ET_EXEC)
    {
        printf("not a executable file...\n");
        return -1;
    }
    
    if (lookup_symbol(&trace_handler) == 1)
    {
        printf("get sym's addr 0x%x(%s)\n", trace_handler.symaddr, trace_handler.symname);
    }
    else
    {
        printf("not find sym: %s\n", trace_handler.symname);
    }
    assert(trace_handler.symaddr != 0x0);
    Elf64_Word orig;

    pid_t pid;
    if ((pid = fork()) < 0)
    {
        perror("fork");
        return -1;
    }
    else if(pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("ptrace traceme");
            return -1;
        }
        printf("exec :%s\n", trace_handler.exec);
        execl(trace_handler.exec, basename(trace_handler.exec), NULL); //no args
        printf("exec failed\n");
        exit(1);
    }
    else
    {
        // sleep(1);
        // if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
        // {
        //     perror("ptrace attach");
        //     return -1;
        // }
        int status = -1;
        wait(&status);
        run_and_watch_breakpoint(&trace_handler, pid);
    }
}


/**
 * struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
*/


#define SHOW_ONE_REGS(user_regs_ptr, regs_name) printf("%s: 0x%x %ld\n", #regs_name, (user_regs_ptr)->regs_name, (user_regs_ptr)->regs_name)

void show_regs(const struct user_regs_struct *user_regs_ptr)
{
    SHOW_ONE_REGS(user_regs_ptr, r15);
    SHOW_ONE_REGS(user_regs_ptr, r14);
    SHOW_ONE_REGS(user_regs_ptr, r13);
    SHOW_ONE_REGS(user_regs_ptr, r12);
    SHOW_ONE_REGS(user_regs_ptr, rbp);
    SHOW_ONE_REGS(user_regs_ptr, rbx);
    SHOW_ONE_REGS(user_regs_ptr, r11);
    SHOW_ONE_REGS(user_regs_ptr, r10);
    SHOW_ONE_REGS(user_regs_ptr, r9);
    SHOW_ONE_REGS(user_regs_ptr, r8);
    SHOW_ONE_REGS(user_regs_ptr, rax);
    SHOW_ONE_REGS(user_regs_ptr, rcx);
    SHOW_ONE_REGS(user_regs_ptr, rdx);
    SHOW_ONE_REGS(user_regs_ptr, rsi);
    SHOW_ONE_REGS(user_regs_ptr, rdi);
    SHOW_ONE_REGS(user_regs_ptr, orig_rax);
    SHOW_ONE_REGS(user_regs_ptr, rip);
    SHOW_ONE_REGS(user_regs_ptr, cs);
    SHOW_ONE_REGS(user_regs_ptr, eflags);
    SHOW_ONE_REGS(user_regs_ptr, rsp);
    SHOW_ONE_REGS(user_regs_ptr, ss);
    SHOW_ONE_REGS(user_regs_ptr, fs_base);
    SHOW_ONE_REGS(user_regs_ptr, gs_base);
    SHOW_ONE_REGS(user_regs_ptr, ds);
    SHOW_ONE_REGS(user_regs_ptr, es);
    SHOW_ONE_REGS(user_regs_ptr, fs);
    SHOW_ONE_REGS(user_regs_ptr, gs);
}

void run_and_watch_breakpoint(const struct handler *trace_handler, pid_t child_pid)
{
    struct user_regs_struct pt_regs;
    Elf64_Xword orig, trap; //ptrace_poketext return a word(8 Bytes)
    Elf64_Addr break_point_addr = trace_handler->symaddr;
    int status = -1;
    if ((orig = ptrace(PTRACE_PEEKTEXT, child_pid, break_point_addr, NULL)) == -1)
    {
        perror("ptrace peektext");
        return;
    }

    trap = (orig & ~0xff) | 0xcc;
    if (ptrace(PTRACE_POKETEXT, child_pid, break_point_addr, trap) != 0)
    {
        perror("ptrace poketext");
        return;
    }

    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) != 0)
    {
        perror("ptrace cont");
        return;
    }

    while(1)
    {
        wait(&status);
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            printf("hit break point: %s(0x%x)\n", trace_handler->symname, break_point_addr);
            if (ptrace(PTRACE_GETREGS, child_pid, NULL, &pt_regs) != 0)
            {
                perror("PTRACE_GETREGS");
                return;
            }

            show_regs(&pt_regs);

            getchar();

            if (ptrace(PTRACE_POKETEXT, child_pid, break_point_addr, orig) != 0)
            {
                perror("ptrace poketext");
                return;
            }

            //exec the origin instruction
            pt_regs.rip -= 1;
            if (ptrace(PTRACE_SETREGS, child_pid, NULL, &pt_regs) != 0)
            {
                perror("PTRACE_SETREGS");
                return;
            }
            //single step, over the breakpoint address
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) != 0)
            {
                perror("PTRACE_SINGLESTEP");
                return;
            }

            wait(NULL);
            //set the break point again.
            if (ptrace(PTRACE_POKETEXT, child_pid, break_point_addr, trap) != 0)
            {
                perror("PTRACE_POKETEXT");
                return;
            }

            //continue 
            if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) != 0)
            {
                perror("ptrace cont");
                return;
            }
        }
        else if (WIFSTOPPED(status))
        {
            printf("stop sig: %d\n", WSTOPSIG(status));
        }
        else if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            printf("Completed tracing, pid: %ld\n", child_pid);
            return;
        }
        else if(WIFCONTINUED(status))
        {
            printf("continue...\n");
        }
        printf("loop...\n");
        fflush(stdout);
    }
}


static int lookup_symbol(struct handler *trace_hander)
{
    Elf64_Sym *symtab;
    Elf64_Shdr *cur_shdr;
    Elf64_Shdr * shdr =  trace_hander->shdr;
    char *strtab;
    char *mem = trace_hander->mem;

    for (int i=0; i < trace_hander->ehdr->e_shnum; i++)
    {
        if (shdr[i].sh_type == SHT_SYMTAB)
        {
            strtab = (char *)&mem[shdr[shdr[i].sh_link].sh_offset];
            symtab = (Elf64_Sym *)&mem[shdr[i].sh_offset];
            printf("----\n");
            for (int j=0; j < shdr[i].sh_size/sizeof(Elf64_Sym); j++)
            {
                if (!strncmp(&strtab[symtab[j].st_name],trace_hander->symname, strlen(trace_hander->symname)))
                {
                    trace_hander->symaddr = symtab[j].st_value;
                    return 1;
                }
                else{
                    printf("get sym: %s\n", &strtab[symtab[j].st_name]);
                }
            }
        }
    }
    return 0;
}
