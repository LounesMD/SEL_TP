#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>


double fibonacci_trap(int n) {
    return (n);
}


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

int main(int argc, char* *argv) {
    // Take the name of the processus and the name of the function to trap.
    if (argc < 3) {
        printf("Error Argument: Not enought argument.\n");
        exit(-1);
    }

    pid_t pid;
    char pid_char[10];
    get_pid(argv[1], pid_char);
    pid = strtol(pid_char, NULL, 10);
    printf("His pid is [%d].\n", pid);
    
    
    // Attach to another process.
    ptrace(PTRACE_ATTACH, pid);

    long addr = find_add_fun(argv[1], argv[2]);
    printf("The address of [%s] is [%ld].\n", argv[2], addr);

    /*
    char command[100];
    char* command_part[] = {"/proc/", pid_char, "/mem"};
    command_writer(command, 100, command_part, 3);
    FILE *mem_proc = NULL;
    mem_proc = fopen(command, "a+");
    */
    printf("Hello.\n");

    int n;
    printf("Valeur de n ?\n");
    scanf("%d", &n);

    printf("Fibonacci of [%d] is [%f].\n", n, fibonacci_trap(n));
    
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_DETACH, pid);

    return 0;
}