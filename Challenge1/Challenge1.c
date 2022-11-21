#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../utilities.h"

// This challenge belongs to Leo Laffeach and Lounès Meddahi
int main(int argc, char *argv[]){
    // The arguments are : The name of the process and the name of the function to trap    
    pid_t tracee_pid;
    long long function_adress;
    

    if(argc != 3){
        printf("Not enough arguments");
        exit(1);
    }

    char pid_char[10];
    get_pid(argv[1], pid_char);
    tracee_pid = strtol(pid_char, NULL, 10);
    // printf("%d \n", tracee_pid );

    printf("The pid to trace is [%d].\n", tracee_pid);


    function_adress = find_addr_fun(argv[1] , argv[2]);
    printf("The adresse of the function [%s] to trace is [%lld].\n", argv[2], function_adress);


    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attach to the pocess
    waitpid(tracee_pid , &status , 0);


    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    FILE * Tracee = fopen( buffer , "wb"); // Here we get all the functions mentionned in the process
    if(Tracee == NULL){
        printf("Tracee failed to open \n");
        exit(-1);
    }

    // Here we put the read pointer on the address of the function
    int i;
    i = fseek(Tracee , function_adress , 0);
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }
    char tab = 0xCC ; // We stock in tab the trap code

    int p;
    p = fwrite(&tab , 1 , 1 ,Tracee); //We write &tab in the process memory instead of the function address
    fclose(Tracee);

    ptrace(PTRACE_DETACH , tracee_pid, NULL, NULL);     // we can now detach from the target process
    waitpid(tracee_pid , &status , 0); // We wait a signal back from the process

    return 0;
    }