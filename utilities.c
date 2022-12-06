#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utilities.h"

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


// Warning : take care to kill all Tracee running if there is some 
// (This function will take the first which can be a wrong one)
int get_pid(char* proc_name, char* pid_char) {
    // Get the pid of the first processus using `pgrep`.
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
        case '\0': // If there is none
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

    if (fscanf(stream, "%c", &line) != EOF) {
        printf("Warning:\n\tTheir is multiple processus [%s] running.\n", proc_name);
    }
    pclose(stream);

    if (!(pid_obtain)) {
        printf("Error pid: No pid obtain.\n");
        exit(-1);
    }

    return 0;
}


long find_addr_fun (char* static_ex_name, char* fun_name) {
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
            // We get the address of the function before verifying if it is the correct one
            if (space_count == 0){
                addr[index_addr] = line;
                index_addr ++;
            }
            // We verify if the fun_name is the correct one.
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