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

// This challenge belongs to Leo Laffaech and Lounès Meddahi

int command_writer(char* command, int length_command, char** command_part, int nb_command_part) {
    // Concatenate all the command_part into command.
    int index = 0;
    int length_command_part = 0;

    for (int i = 0; i < nb_command_part; i++ ) {
        length_command_part = strlen(command_part[i]);
        if (index + length_command_part > length_command) {
            printf("Error Size: the command buffer is not big enought.\n");
            exit(-1);
        }
        for (int j = 0; j < length_command_part; j++) {
            command[index + j] = command_part[i][j];
        }
        index += length_command_part;
    }

    command[index + 1] = '\0';

    return 0;
}


int get_pid(char* proc_name, char* pid_char) {
    // Get the pid of the first processus using `pgreg`.
    char command[100] = {0};
    char* command_part[] = {"pgrep ", proc_name};
    command_writer(command, 100, command_part, 2);

    FILE * stream = NULL;
    stream = popen(command, "r");
    if (!stream) {
        printf("Error open.\n");
        exit(-1);
    }

    char line;
    int end;
    int pid_obtain = 0;
    int index = 0;
    do {
        end = fscanf(stream, "%c", &line);
        switch (line)
        {
        case '\0':
            printf("Error Processus: no such processus is running.\n");
            exit(-1);
            break;
        
        case '\n':
            pid_obtain = 1;
            pid_char[index] = '\0';
            break;

        default:
            pid_char[index] = line;
            index ++;
        }

    } while (end != EOF && !(pid_obtain));
    pclose(stream);

    if (!(pid_obtain)) {
        printf("Error pid: No pid obtain.\n");
        exit(-1);
    }

    return 0;
}

long function_offset(char* pid, char* function_name) {
    // Get the offset of the function in the binary.
    char command[100] = {0};
    char* command_part[] = {"nm -n /proc/", pid, "/exe | grep ", function_name};
    command_writer(command, 100, command_part, 4);

    FILE * stream = NULL;
    stream = popen(command, "r");
    if (!stream) {
        printf("Error open.\n");
        exit(-1);
    }

    char line;
    int end;
    int offset_obtain = 0;
    int index = 0;
    char offset_char[100] = {0};
    do {
        end = fscanf(stream, "%c", &line);
        switch (line)
        {
        case '\0':
            printf("Error Function: no such function is running.\n");
            exit(-1);
            break;
        
        case '\n':
            offset_obtain = 1;
            offset_char[index] = '\0';
            break;

        default:
            offset_char[index] = line;
            index ++;
        }

    } while (end != EOF && !(offset_obtain));
    pclose(stream);

    if (!(offset_obtain)) {
        printf("Error offset: No offset obtain.\n");
        exit(-1);
    }

    long offset = strtol(offset_char, NULL, 16);

    return offset;
}




int main(int argc, char *argv[]){
    // The arguments are : 
    //  1) The name of the process
    //  2) The name of the target function to replace
    //  3) Size of the cache code
    if(argc != 4){
        printf("Not enough arguments");
        exit(1);
    }
    pid_t tracee_pid;
    long function_adress;
    char pid_char[10];
    int cacheSize;


    get_pid(argv[1], pid_char);
    tracee_pid = strtol(pid_char, NULL, 10);
    printf("The pid to trace is [%d].\n", tracee_pid);

    function_adress = function_offset(pid_char , argv[2]);
    printf("The adresse of the function [%s] to replace is [%ld].\n", argv[2], function_adress);

    cacheSize = atoi(argv[4]);    

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attached to the pocess
    waitpid(tracee_pid , &status , 0);


    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    FILE * Tracee = fopen( buffer , "r+"); // Here we get all the functions mentionned in the process
    if(Tracee == NULL){
        printf("Tracee failed to open \n");
        exit(-1);
    }

    // Here we put the read pointer on the address of the function to replace
    int i = fseek(Tracee , function_adress , 0);
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }



    char tab = 0xCC ;
    char sauvegarde1[1];    
    fread( sauvegarde1, 1 , 1 , Tracee); // Before writing the trap, we make a backup of the line
    fseek(Tracee , function_adress , 0);
    fwrite(&tab , 1 , 1 ,Tracee); // We write the trap to stop the traced process
    fclose(Tracee);

    ptrace(PTRACE_CONT , tracee_pid, NULL, NULL); // We restart the process
    waitpid(tracee_pid , &status , 0); 


    struct user_regs_struct original_regs;
    struct user_regs_struct modified_regs;

    ptrace(PTRACE_GETREGS , tracee_pid , 0 , &original_regs ); // We keep a backup of the original registers 
    ptrace(PTRACE_GETREGS , tracee_pid , 0 , &modified_regs ); // And we take an other copy in order to call posix_memalign and mprotect

    
    
    
    // Because the traced process is compiled using the -static command, we can find the adresse of posix_memalign in order to launch it
    long posix_memalign_adress = function_offset(pid_char , "posix_memalign"); 

    modified_regs.rax = posix_memalign_adress;
    modified_regs.rdi = original_regs.rdi; // We keep the original parameter which is already a pointer
    modified_regs.rsi = 0; // We use 0 for the alignement
    modified_regs.rdx = cacheSize; // And the last parameter for the cachesize

    ptrace(PTRACE_SETREGS , tracee_pid , NULL , NULL);


    // We relaunch the traced process to creat a memory space (posix_memalign) with the new registers
    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    waitpid(tracee_pid , &status , 0); 

    // Now, we can use mprotect to be able to read/write/exec the function that we are going to write
    struct user_regs_struct modified_regs_3;
    ptrace(PTRACE_GETREGS , tracee_pid , 0 , &modified_regs_3 );
    long adresse_to_write = modified_regs_3.rdi; // In the first parameter of posix_memalign, we will have the adress to write


    // We use a new register in order to execute the mprotect
    struct user_regs_struct modified_regs_2;
    ptrace(PTRACE_GETREGS, tracee_pid, 0, &modified_regs_2);

    long mprotect_adress = function_offset(pid_char , "mprotect"); 
    modified_regs_2.rax = mprotect_adress;

    modified_regs_2.rdi = adresse_to_write;
    modified_regs_2.rsi = cacheSize; // 
    modified_regs_2.rdx = PROT_EXEC | PROT_READ | PROT_WRITE;

    ptrace(PTRACE_SETREGS, tracee_pid, 0, &modified_regs_2); // We can now set the register and relaunch the process
    ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    waitpid(tracee_pid , &status , 0); 



    unsigned char inst[24] = {0xf3 , 0x0f ,  0x1e , 0xfa ,
                              0x55 ,
                              0x48 , 0x89 , 0xe5 ,
                              0x89 , 0x7d , 0xfc ,
                              0x89 , 0x75 , 0xf8 ,
                              0x8b , 0x55  , 0xfc ,
                              0x8b , 0x45 , 0xf8 ,
                              0x01 , 0xd0 ,
                              0x5d ,
                              0xc3 };

    // The above instructions can be found by running : objdump -d Interm
    // Now, we open the memory in order to write those instructions
    buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    Tracee = fopen( buffer , "wb");
    if(Tracee == NULL){
        printf("Tracee failed to open \n");
        exit(-1);
    }

    i = fseek(Tracee , adresse_to_write, 0); 
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }

    fwrite(inst , 1 , 24 ,Tracee);

    
    fseek(Tracee , function_adress , 0);  
    fwrite(&sauvegarde1 , 1 , 1 ,Tracee); // Now, we can remove the trap instruction and replace it by the backup


    fclose(Tracee);

    
    // We hand over the original registers
    ptrace(PTRACE_SETREGS, tracee_pid, 0, &original_regs);
    ptrace(PTRACE_DETACH, tracee_pid, NULL, NULL);

    return 0;
    }   