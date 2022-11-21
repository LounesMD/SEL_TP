#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include "../utilities.h"

#define ARG1 1;
#define ARG2 1;
// This challenge belongs to Leo Laffaech and Lounès Meddahi

int main(int argc, char *argv[]){
    // The arguments are : The name of the process, the name of the target function to replace and the name of the function to execute    
    if(argc < 4){
        printf("Not enough arguments");
        exit(1);
    }

    // We have 2 optionals arguments for the function to execute.
    int arg1 = ARG1;
    int arg2 = ARG2;
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "-arg1")) {
            if ((i+1 >= argc) || (sscanf(argv[i+1],"%d",&arg1) != 1)) {
                printf("Argument Error: Invalide <arg1> argument.\n");
                exit(-1);
            }
        }
        if (!strcmp(argv[i], "-arg2")) {
            if ((i+1 >= argc) || (sscanf(argv[i+1],"%d",&arg2) != 1)) {
                printf("Argument Error: Invalide <arg2> argument.\n");
                exit(-1);
            }
        }
        
    }

    // Get the pid of the traced process.
    char pid_char[10];
    get_pid(argv[1], pid_char);
    pid_t tracee_pid = strtol(pid_char, NULL, 10);
    printf("%d \n", tracee_pid );

    printf("The process trace is [%s].\n", argv[1]);
    printf("The pid to trace is [%d].\n", tracee_pid);

    // Get the addresses of the functions
    long long function_adress = find_addr_fun(argv[1], argv[2]);
    printf("The adresse of the function [%s] to replace is [%lld].\n", argv[2], function_adress);
    long long target_function_adresse = find_addr_fun(argv[1], argv[3]);
    printf("The adresse of the target function [%s] is [%lld].\n", argv[3], target_function_adresse);

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attached to the pocess
    waitpid(tracee_pid , &status , 0);


    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    FILE* traced_process_mem = fopen( buffer , "r+"); // Here we get all the functions mentionned in the process
    if(traced_process_mem == NULL){
        printf("traced_process_mem failed to open.\n");
        exit(-1);
    }

    // Here we put the read pointer on the address of the function
    if(fseek(traced_process_mem , function_adress , 0) != 0){
        printf("fseek failed.\n");
        exit(-1);
    }
    
    char trap_instru = 0xCC ; // Trap pour récupérer le contrôle du processus

    char original_instru[3];
    for (int i = 0; i < 3; i++) {
        fread(original_instru + i, 1, 1, traced_process_mem);
    }

    fseek(traced_process_mem , function_adress , 0);
    fwrite(&trap_instru, 1, 1, traced_process_mem); //We write &tab in the process memory instead of the function address to stop when the process
    fclose(traced_process_mem);
    traced_process_mem = NULL;

    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL); // We use to stop the process when the process is traped while keeping the control
    waitpid(tracee_pid, &status, 0); 

    //  Now we can take the registers.
    // A first one as a copy and a second one for modification

    // Get the value of the register.
    struct user_regs_struct original_regs; // to restore register.
    ptrace(PTRACE_GETREGS, tracee_pid, NULL, &original_regs); 

    struct user_regs_struct modified_regs;
    ptrace(PTRACE_GETREGS, tracee_pid, NULL, &modified_regs);

    
    traced_process_mem = fopen( buffer , "r+"); // Here we get all the functions mentionned in the process
    if(traced_process_mem == NULL){
        printf("traced_process_mem failed to open.\n");
        exit(-1);
    }

    // We placed ourself at the functione_address.
    if(fseek(traced_process_mem, function_adress, 0)){
        printf("fseek failed.\n");
        exit(-1);
    }
    
    modified_regs.rip = function_adress;

    char indirect_call_instru[2] = {0xff, 0xd0}; // We stock in tab the call to rax    
    fwrite(&indirect_call_instru[0], 1, 1, traced_process_mem);
    fwrite(&indirect_call_instru[1], 1, 1, traced_process_mem);
    
    fwrite(&trap_instru, 1, 1, traced_process_mem); //We trap the traced process after the execution of the function.
    fclose(traced_process_mem);
    traced_process_mem = NULL;

    // we modified the register.
    modified_regs.rdi = arg1;
    modified_regs.rsi = arg2;
    modified_regs.rax = target_function_adresse;
    ptrace(PTRACE_SETREGS, tracee_pid, NULL, &modified_regs);

    // We restart the traced process to execute our function.
    ptrace(PTRACE_CONT, tracee_pid,  NULL, NULL);
    waitpid(tracee_pid, &status, 0); 

    /// We get the return value of our function.  
    struct user_regs_struct modified_regs_2;
    ptrace(PTRACE_GETREGS, tracee_pid, NULL, &modified_regs_2);
    printf("%s(%d, %d) = %lld\n", argv[3], arg1, arg2, modified_regs_2.rax);


    traced_process_mem = fopen( buffer , "r+"); // Here we get all the functions mentionned in the process
    if(traced_process_mem == NULL){
        printf("traced_process_mem failed to open.\n");
        exit(-1);
    }
    // Restore the original registers.
    fseek(traced_process_mem, function_adress, 0);
    for (int i = 0; i < 3; i++){
        fwrite(original_instru + i, 1, 1, traced_process_mem);
    }

    original_regs.rip = function_adress;

    ptrace(PTRACE_SETREGS, tracee_pid, NULL, &original_regs);

    ptrace(PTRACE_DETACH, tracee_pid, NULL, NULL);
    waitpid(tracee_pid, &status, 0); 

    return 0;
}