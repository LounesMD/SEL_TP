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
    // The arguments are : The name of the process, the name of the target function to replace and the name of the function to execute
    pid_t tracee_pid;
    long long function_adress;
    

    if(argc != 4){
        printf("Not enough arguments");
        exit(1);
    }

    char pid_char[10];
    get_pid(argv[1], pid_char);
    tracee_pid = strtol(pid_char, NULL, 10);
    printf("%d \n", tracee_pid );

    printf("The pid to trace is [%d].\n", tracee_pid);


    function_adress = find_add_fun(argv[1] , argv[2]);
    printf("The adresse of the function [%s] to replace is [%lld].\n", argv[2], function_adress);

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // We are now attached to the pocess
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
    
    char tab = 0xCC ; // Trap pour récupérer le contrôle du processus

    int p;
    p = fwrite(&tab , 1 , 1 ,Tracee); //We write &tab in the process memory instead of the function address to stop when the process
    fclose(Tracee);

    ptrace(PTRACE_CONT , tracee_pid, NULL, NULL); // We use to stop the process when the process is traped while keeping the control
    waitpid(tracee_pid , &status , 0); 

    //  Now we can take the registers.
    // A first one as a copy and a second one for modification

    // Point n°2 : On récupère la valeur des registres
    struct user_regs_struct original_regs;
    struct user_regs_struct modified_regs;

    ptrace(PTRACE_GETREGS , tracee_pid , NULL , original_regs ); 
    ptrace(PTRACE_GETREGS , tracee_pid , NULL , modified_regs );
    // Point n°3 : 

    // Ici on ne peut pas directement modifier la prochaine instruction à éxecuter (donc le registre rip) car on aurait pls pb :
    // retour de la fonction , accessibilité de la fonction à executer etc ...
    // Pour ce faire, on va faire un appel indirect en passant par le registre rax qui permet ???



    // Supposons que l'écriture de la fonction dans le registre actuel a fonctionné ( appel indirect suivi d'un trap) :


    int param;




    // ???
    // Dans cette partie je suis censé savoir le nombre de bloc écrit pour ensuite pouvoir mettre le trap
    // Car on aura écrit de function_adress à function_adress + idx 
    int indx = 0;

    // Là on écrit le trap qui suit l'écriture de la fonction
    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    FILE * Tracee = fopen( buffer , "wb"); // Here we get all the functions mentionned in the process
    if(Tracee == NULL){
        printf("Tracee failed to open \n");
        exit(-1);
    }

    int i;
    i = fseek(Tracee , function_adress + indx, 0);
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }
    char tab = 0xCC ; // We stock in tab the trap code
    int p;
    p = fwrite(&tab , 1 , 1 ,Tracee); //We write &tab in the process memory instead of the function address
    fclose(Tracee);


    // On continue le processus pour executer la fonction 
    ptrace(PTRACE_CONT , tracee_pid ,  NULL , NULL);
    waitpid(tracee_pid , &status , 0); 

    /// Maintenant on va récupèrer le résultat de la fonction  
    struct user_regs_struct modified_regs_2;
    ptrace(PTRACE_GETREGS , tracee_pid , NULL , modified_regs_2);








    // Point n°6 : Restauration de la valeur initiale des registres
    ptrace(PTRACE_SETREGS , tracee_pid , NULL , original_regs );

    // Redémarrage du processus 
    ptrace(PTRACE_DETACH , tracee_pid , NULL , NULL);

    return 0;
    }