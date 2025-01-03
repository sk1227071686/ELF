#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

static void Usage(void)
{
    printf("Usage: ./a.out <executable> \n");
    exit(1);
}

int main(int argc, char* argv[])
{
    int fd;
    char *elf_in_memory;
    char *string_table;
    struct stat file_stat;

    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;

    if (argc != 2 || argv[1][0] == '\0')
    {
        Usage();
    }

    const char *filename = argv[1];
    //open elf file.
    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }
    //get file size.
    if (fstat(fd, &file_stat) < 0)
    {
        perror("fstat");
        return -1;
    }
    //mmap elf file into memory.
    elf_in_memory = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_in_memory == MAP_FAILED)
    {
        perror("mmap");
        return -1;
    }

    /**
     * Elf header at offset 0.
     * we should judge elf magic first.
    */
    if (elf_in_memory[0] != 0x7f || strncmp(&elf_in_memory[1], "ELF", 3))
    {
        printf("ELF magic check failed.\n");
        return -1;
    }

    ehdr = (Elf64_Ehdr *)elf_in_memory;
    shdr = (Elf64_Shdr *)&elf_in_memory[ehdr->e_shoff];
    phdr = (Elf64_Phdr *)&elf_in_memory[ehdr->e_phoff];

    //we only parse executable 
    if (ehdr->e_type != ET_EXEC)
    {
        printf("not a executable file...\n");
        return -1;
    }

    printf("Section list: \nName\taddress\t\n");
    string_table = &elf_in_memory[shdr[ehdr->e_shstrndx].sh_offset];
    for (int i=0; i < ehdr->e_shnum; i++)
    {
        printf("%s\t%#x\t\n", &string_table[shdr[i].sh_name], shdr[i].sh_addr);
    }
    
    printf("Segment list: \nName\taddress\t\n");
    for (int i=0; i < ehdr->e_phnum; i++)
    {
        switch (phdr[i].p_type)
        {
        case PT_NULL:
            printf("NULL\t%#x\t\n", phdr[i].p_vaddr);
            break;
        case PT_LOAD:
            if (phdr[i].p_offset == 0)
                printf("TEXT\t%#x\t\n", phdr[i].p_vaddr);
            else
                printf("DATA\t%#x\t\n", phdr[i].p_vaddr);
            break;      
        case PT_DYNAMIC:
            printf("DYNAMIC\t%#x\t\n", phdr[i].p_vaddr);
            break;
        case PT_INTERP:
            printf("interpreter\t%s\t\n", &elf_in_memory[phdr[i].p_offset]);
            break;
        case PT_NOTE:
            printf("NOTE\t%#x\t\n", phdr[i].p_vaddr);
            break;
        case PT_PHDR:
            printf("PHDR\t%#x\t\n", phdr[i].p_vaddr);
            break;
        default:
            break;
        }
    }

}
