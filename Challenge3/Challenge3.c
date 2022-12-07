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

    long function_adress = function_offset(pid_char , argv[2]);
    printf("The adresse of the function [%s] to replace is [%ld].\n", argv[2], function_adress);

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
    int i = fseek(traced_process_mem, function_adress, 0);
    if(i != 0){
        printf("Error: fseek failed.\n");
        exit(-1);
    }

    char tab = 0xCC ;
    char sauvegarde1[1];    
    fread(sauvegarde1, 1, 1, traced_process_mem); // Before writing the trap, we make a backup of the line
    fseek(traced_process_mem, function_adress, 0);
    fwrite(&tab, 1, 1, traced_process_mem); // We write the trap to stop the traced process
    fclose(traced_process_mem);
    traced_process_mem = NULL;

    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL); // We restart the process
    waitpid(tracee_pid, &status, 0); 


    struct user_regs_struct original_regs;
    struct user_regs_struct modified_regs;

    ptrace(PTRACE_GETREGS, tracee_pid, 0, &original_regs); // We keep a backup of the original registers 
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs); // And we take an other copy in order to call posix_memalign and mprotect

    
    // Because the traced process is compiled using the -static command, we can find the adresse of posix_memalign in order to launch it
    long posix_memalign_adress = function_offset(pid_char, "posix_memalign"); 

    modified_regs.rax = posix_memalign_adress;
    modified_regs.rdi = original_regs.rdi; // We keep the original parameter which is already a pointer
    modified_regs.rsi = 0; // We use 0 for the alignement
    modified_regs.rdx = cacheSize; // And the last parameter for the cachesize

    ptrace(PTRACE_SETREGS, tracee_pid, NULL, NULL);


    // We relaunch the traced process to creat a memory space (posix_memalign) with the new registers
    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    waitpid(tracee_pid, &status, 0); 

    // Now, we can use mprotect to be able to read/write/exec the function that we are going to write
    struct user_regs_struct modified_regs_3;
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs_3);
    long adresse_to_write = modified_regs_3.rdi; // In the first parameter of posix_memalign, we will have the adress to write


    // We use a new register in order to execute the mprotect
    struct user_regs_struct modified_regs_2;
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs_2);

    long mprotect_adress = function_offset(pid_char , "mprotect"); 
    modified_regs_2.rax = mprotect_adress;

    modified_regs_2.rdi = adresse_to_write;
    modified_regs_2.rsi = cacheSize; 
    modified_regs_2.rdx = PROT_EXEC | PROT_READ | PROT_WRITE;

    // We can now set the register and relaunch the process
    ptrace(PTRACE_SETREGS, tracee_pid, 0, &modified_regs_2);
    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    waitpid(tracee_pid, &status, 0); 

    unsigned char inst[INST_NUMBER] = {INST};

    // Now, we open the memory in order to write those instructions
    snprintf(buffer, 20, "/proc/%d/mem", tracee_pid);
    traced_process_mem = fopen(buffer, "wb");
    if(traced_process_mem == NULL){
        printf("Error: %s failed to open.\n", argv[1]);
        exit(-1);
    }
 
    if(fseek(traced_process_mem, adresse_to_write, 0) != 0){
        printf("Error: fseek failed.\n");
        exit(-1);
    }

    fwrite(inst, 1, 24, traced_process_mem);

    
    fseek(traced_process_mem, function_adress, 0);  
    fwrite(&sauvegarde1, 1, 1, traced_process_mem); // Now, we can remove the trap instruction and replace it by the backup


    fclose(traced_process_mem);

    
    // We hand over the original registers
    ptrace(PTRACE_SETREGS, tracee_pid, 0, &original_regs);
    ptrace(PTRACE_DETACH, tracee_pid, NULL, NULL);

    return 0;
    }   