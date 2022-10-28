#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>

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


// Warning : take care to kill all Tracee running if there is some (This function will take the first wich can be not the good one)
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


long find_add_fun (char* static_ex_name, char* fun_name) {
    // Search in the addresses of the exec name to find the fun_name address.
    char command[50] = {0};
    char* command_part[] = {"nm ", static_ex_name};
    command_writer(command, 50, command_part, 2);

    FILE *stream = NULL;
    stream = popen(command, "r");
    if (!stream) {
        printf("Error Memory: can not open the stream\n");
        exit(-1);
    }

    int command_found = 0;
    char line;
    int end;
    char addr[20] = {0};
    int index_addr = 0;
    int space_count = 0;
    int same_fun = 1;
    int index_fun = 0;

    do {
        end = fscanf(stream, "%c", &line);
        
        // searching for the fun_name
        switch (line)
        {
        case '\n':
            if (same_fun == 1) {
                command_found = 1;
            } else {
                same_fun = 1;
                index_addr = 0;
                index_fun = 0;
                space_count = 0;
            }
            break;
        
        case ' ':
            space_count ++;
            break;

        default:
            if (space_count == 0){
                addr[index_addr] = line;
                index_addr ++;
            }
            if (space_count == 2 && same_fun) {
                if (line == fun_name[index_fun]) {
                    index_fun ++;
                } else {
                    same_fun = 0;
                }
            }
            break;
        }

    } while ((end != EOF) && !(command_found));

    addr[index_addr] = '\0';

    pclose(stream);
    if (!command_found) {
        printf("Error Fun: Function not found.\n");
        exit(-1);
    }

    return strtoll(addr, NULL, 16);
}


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
    printf("%d \n", tracee_pid );

    printf("The pid to trace is [%d].\n", tracee_pid);


    function_adress = find_add_fun(argv[1] , argv[2]);
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