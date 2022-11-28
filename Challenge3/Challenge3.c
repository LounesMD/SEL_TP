#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

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

// We want a function that takes as a param the pid of a process, the name of a function of this process and returns the adress offset of this function in this process
// We will use the ptrace function to read the memory of the process and the nm function to get the offset of the function in the binary
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
    //  3) The name of the function to execute
    //  4) Size of the cache code

    pid_t tracee_pid;
    long function_adress;
    

    if(argc != 5){
        printf("Not enough arguments");
        exit(1);
    }

    char pid_char[10];
    get_pid(argv[1], pid_char);
    tracee_pid = strtol(pid_char, NULL, 10);
    printf("%d \n", tracee_pid );

    printf("The pid to trace is [%d].\n", tracee_pid);


    function_adress = function_offset(pid_char , argv[2]);
    printf("The adresse of the function [%s] to replace is [%ld].\n", argv[2], function_adress);



    long target_function_adresse;
    target_function_adresse = function_offset(pid_char , argv[3]);
    printf("The adresse of the target function [%s] is [%ld].\n", argv[3], target_function_adresse);

    int cacheSize = atoi(arbv[4])
    

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attached to the pocess
    waitpid(tracee_pid , &status , 0);



    // Maintenant que nous sommes attachés au processus on va récupèrer l'accès à sa mémoire

    // Etape 1 :
    // On va écrire une intruction trap au niveau d'un fonction foo qu'on sait être appelée (chall 1)
    // Un fois le processus trappé, on va relancer le processus pour qu'il se bloque une fois le trap rencontré
    
    // Etape 2 :
    // On va modifier l'instruction à executer (pour y mettre le posix_memalign)
    // On va donner en paramètres :
    // 1) L'adresse du pointeur de la fonction foo dans regs.rdi
    // 2) alignment dans regs.rsi
    // 3) le nombre d'octets à allouer dans regs.rdx
    // On met un trap ensuite comme ça on va pouvoir récupérer le resultat (donc la valeur du pointeur )    
    // On fait appel à mprotect pour pouvoir modifier et executer la zone mémoire eu grâce à posix_memalign (Challenge 2)
    
    // Etape 3 (challenge 3):
    // On va écrire le code executable* 
    // Pour ce faire, on va écrire dans un fichier une fonction, récupérer son code assembleur (avec objdump -d Interm) :
    // 1129:       f3 0f 1e fa             endbr64                  0xf30f1efa
    // 112d:       55                      push   %rbp              0x55
    // 112e:       48 89 e5                mov    %rsp,%rbp         0x4889e5
    // 1131:       89 7d fc                mov    %edi,-0x4(%rbp)   0x897dfc
    // 1134:       89 75 f8                mov    %esi,-0x8(%rbp)   0x8975f8
    // 1137:       8b 55 fc                mov    -0x4(%rbp),%edx   0x8b55fc
    // 113a:       8b 45 f8                mov    -0x8(%rbp),%eax   0x8b45f8
    // 113d:       01 d0                   add    %edx,%eax         0x01d0
    // 113f:       5d                      pop    %rbp              0x5d
    // 1140:       c3                      retq                     0xc3

    // Etape 4 :
    // On relance le processus pour qu'il s'execute jusqu'au trap
    // On retire toutes les instructions écrites (memalign, etc) et on remet les instructions initiales (Challenge 2)
    // On remet le registre original



    return 0;
    }   