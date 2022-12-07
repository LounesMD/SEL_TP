#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../utilities.h"

// This challenge belongs to Léo Laffeach and Lounès Meddahi.
int main(int argc, char *argv[]){
    /*
        Arguments are: 
         [1] The name of the process;
         [2] the name of the function to trap. 
    */
    if(argc < 3){
        printf("Error: Not enough arguments.\n");
        exit(1);
    }

    pid_t tracee_pid;
    long long function_adress;
    char pid_char[10];

    get_pid(argv[1], pid_char);
    tracee_pid = strtol(pid_char, NULL, 10);
    printf("The pid to trace is [%d].\n", tracee_pid);

    function_adress = find_addr_fun(argv[1] , argv[2]);
    printf("The adresse of the function [%s] to trace is [%lld].\n", argv[2], function_adress);

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attach to the pocess
    waitpid(tracee_pid , &status , 0);

    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    FILE * traced_process_mem = NULL;
    traced_process_mem = fopen( buffer , "wb"); // Here we get all the functions mentionned in the process
    if(traced_process_mem == NULL){
        printf("Error: %s failed to open.\n", argv[1]);
        exit(-1);
    }

    // Here we put the read pointer on the address of the function
    if(fseek(traced_process_mem , function_adress , 0) != 0){
        printf("Error: fseek failed.\n");
        exit(-1);
    }

    char tab = 0xCC ; // We stock in tab the trap code
    
    fwrite(&tab , 1 , 1 ,traced_process_mem); //We write &tab in the process memory instead of the function address
    fclose(traced_process_mem);

    ptrace(PTRACE_DETACH , tracee_pid, NULL, NULL);     // we can now detach from the target process
    waitpid(tracee_pid , &status , 0); // We wait a signal back from the process

    return 0;
    }