#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../utilities.h"

#define INST_NUMBER 24
// Code of "somme" in `Interm.c` in hexa.
#define INST 0xf3, 0x0f,  0x1e, 0xfa,   \
             0x55,                      \
             0x48, 0x89, 0xe5,          \
             0x89, 0x7d, 0xfc,          \
             0x89, 0x75, 0xf8,          \
             0x8b, 0x55, 0xfc,          \
             0x8b, 0x45, 0xf8,          \
             0x01, 0xd0,                \
             0x5d,                      \
             0xc3 
/* 
    The above instructions can be obtained by running : 
        objdump -d Interm
    or
        make Get_Hexa_Somme
*/

// This challenge belongs to Léo Laffeach and Lounès Meddahi.
int main(int argc, char *argv[]){
    /*
        Arguments are: 
         [1] The name of the process;
         [2] The name of the target function to replace;
    */
    if(argc < 3){
        printf("Error: Not enough arguments.\n");
        exit(1);
    }

    pid_t tracee_pid;
    char pid_char[10];

    get_pid(argv[1], pid_char);
    tracee_pid = strtol(pid_char, NULL, 10);
    printf("The pid to trace is [%d].\n", tracee_pid);

    long function_address = function_offset(pid_char , argv[2]);
    printf("The address of the function [%s] to trap is [%ld].\n", argv[2], function_address);

    int cacheSize = INST_NUMBER;    

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attached to the pocess
    waitpid(tracee_pid, &status, 0);


    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem", tracee_pid);
    FILE * traced_process_mem = NULL;
    traced_process_mem = fopen(buffer, "r+"); // Here we get all the functions mentionned in the process
    if(traced_process_mem == NULL){
        printf("Error: %s failed to open.\n", argv[1]);
        exit(-1);
    }

    // Here we put the read pointer on the address of the function to replace
    int fseek_error = fseek(traced_process_mem, function_address, 0);
    if(fseek_error != 0){
        printf("Error: First fseek failed with error %d.\n", fseek_error);
        exit(-1);
    } 

    char trap_instru = 0xCC ;
    char sauvegarde1[3];    
    fread(sauvegarde1, 1, 3, traced_process_mem); // Before writing the trap, we make a backup of the line
    
    fseek_error = fseek(traced_process_mem, function_address, 0);
    if(fseek_error != 0){
        printf("Error: Second fseek failed with error %d.\n", fseek_error);
        exit(-1);
    } 

    fwrite(&trap_instru, 1, 1, traced_process_mem); // We write the trap to stop the traced process
    fclose(traced_process_mem);
    traced_process_mem = NULL;

    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL); // We restart the process
    waitpid(tracee_pid, &status, 0);

    struct user_regs_struct original_regs;
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &original_regs); // We keep a backup of the original registers 

    // And we take an other copy in order to call posix_memalign
    struct user_regs_struct modified_regs;
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs); 
    
    // Because the traced process is compiled using the -static command, 
    // we can find the address of posix_memalign in order to launch it
    long posix_memalign_address = function_offset(pid_char, "posix_memalign"); 

    modified_regs.rax = posix_memalign_address;
    modified_regs.rdi = original_regs.rdi; // We keep the original parameter which is already a pointer
    modified_regs.rsi = 0; // We use 0 for the alignement
    modified_regs.rdx = cacheSize; // And the last parameter for the cachesize

    ptrace(PTRACE_SETREGS, tracee_pid, 0, &modified_regs);

    char indirect_call_instru[2] = {0xff, 0xd0};
    
    traced_process_mem = fopen(buffer, "r+");
    if(traced_process_mem == NULL){
        printf("Error: %s failed to open.\n", argv[1]);
        exit(-1);
    }
    
    fseek_error = fseek(traced_process_mem, function_address, 0);
    if(fseek_error != 0){
        printf("Error: Third fseek failed with error %d.\n", fseek_error);
        exit(-1);
    } 

    // We do an inderect call to rax.
    fwrite(indirect_call_instru, 1, 2, traced_process_mem);
    fwrite(&trap_instru, 1, 1, traced_process_mem);

    fclose(traced_process_mem);
    traced_process_mem = NULL;

    // We relaunch the traced process to creat a memory space (posix_memalign) with the new registers
    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    waitpid(tracee_pid, &status, 0); 

    // Now, we can use mprotect to be able to read/write/exec the function that we are going to write
    struct user_regs_struct modified_regs_2;
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs_2);

    printf("Value of rax after posix_memalign [%lld]\n", modified_regs_2.rax);

    long address_to_write = modified_regs_2.rdi; // In the first parameter of posix_memalign, we will have the address to write

    // We use a new register in order to execute the mprotect
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs);

    long mprotect_address = function_offset(pid_char, "mprotect"); 
    modified_regs.rax = mprotect_address;

    modified_regs.rdi = modified_regs_2.rdi;
    modified_regs.rsi = cacheSize; 
    modified_regs.rdx = PROT_EXEC | PROT_READ | PROT_WRITE;

    // We can now set the register and relaunch the process
    ptrace(PTRACE_SETREGS, tracee_pid, 0, &modified_regs);


    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    waitpid(tracee_pid, &status, 0); 

    printf("Value of rax after memprotect [%lld]\n", modified_regs_2.rax);

    unsigned char inst[INST_NUMBER] = {INST};

    // Now, we open the memory in order to write those instructions
    traced_process_mem = fopen(buffer, "wb");
    if(traced_process_mem == NULL){
        printf("Error: %s failed to open.\n", argv[1]);
        exit(-1);
    }
 
    if(fseek(traced_process_mem, address_to_write, 0) != 0){
        printf("Error: fseek to address_to_write failed.\n");
        exit(-1);
    }

    // We write the instruction.
    fwrite(inst, 1, INST_NUMBER, traced_process_mem);

    // We restore the previous instruction.
    function_address = function_offset(pid_char , argv[2]);

    fseek_error = fseek(traced_process_mem, function_address, 0);
    if(fseek_error != 0){
        printf("Error: Fourth fseek failed with error %d.\n", fseek_error);
        exit(-1);
    } 

    fwrite(&sauvegarde1, 1, 3, traced_process_mem); // Now, we can remove the trap instruction and replace it by the backup

    fclose(traced_process_mem);
    traced_process_mem = NULL;

    
    // We hand over the original registers
    ptrace(PTRACE_SETREGS, tracee_pid, 0, &original_regs);
    ptrace(PTRACE_DETACH, tracee_pid, NULL, NULL);

    return 0;
} 