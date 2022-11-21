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
    // The arguments are : The name of the process, the name of the target function to replace and the name of the function to execute
    pid_t tracee_pid;
    long function_adress;
    

    if(argc != 4){
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
    // target_function_adresse = strtoll(argv[3] , NULL , 16);
    // printf("The adresse of the target function [%s] is [%ld].\n", argv[3], target_function_adresse);

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

    // Here we put the read pointer on the address of the function
    int i;
    i = fseek(Tracee , function_adress , 0);
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }
    
    char tab = 0xCC ; // Trap pour récupérer le contrôle du processus

    int p;
    char inst[3];
    fread( inst, 1 , 3 , Tracee);
    printf(" %x \n" , (unsigned char)inst[0]);
    printf(" %x \n" , (unsigned char)inst[1]);
    printf(" %x \n" , (unsigned char)inst[2]);

    fseek(Tracee , function_adress , 0);
    p = fwrite(&tab , 1 , 1 ,Tracee); //We write &tab in the process memory instead of the function address to stop when the process
    
    fclose(Tracee);

    ptrace(PTRACE_CONT , tracee_pid, NULL, NULL); // We use to stop the process when the process is traped while keeping the control
    waitpid(tracee_pid , &status , 0); 

    //  Now we can take the registers.
    // A first one as a copy and a second one for modification

    // Point n°2 : On récupère la valeur des registres
    struct user_regs_struct original_regs;
    struct user_regs_struct modified_regs;

    ptrace(PTRACE_GETREGS , tracee_pid , 0 , &original_regs ); 
    ptrace(PTRACE_GETREGS , tracee_pid , 0 , &modified_regs );

    // Point n°3 : 

    // Ici on ne peut pas directement modifier la prochaine instruction à éxecuter (donc le registre rip) car on aurait pls pb :
    // retour de la fonction , accessibilité de la fonction à executer etc ...
    // Pour ce faire, on va faire un appel indirect en passant par le registre rax qui permet ???

    // Là on écrit le trap qui suit l'écriture de la fonction
    buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    Tracee = fopen( buffer , "wb"); // Here we get all the functions mentionned in the process
    if(Tracee == NULL){
        printf("Tracee failed to open \n");
        exit(-1);
    }

    //// On va pouvoir écrire la fonction à executer 
    i = fseek(Tracee , function_adress, 0); // On se place au niveau de l'ancienne fonction
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }

    printf("test %lld ", original_regs.rip);
    
    modified_regs.rip = function_adress;
    
    tab = 0xff; // We stock in tab the call to rax     
    p = fwrite(&tab , 1 , 1 ,Tracee); //
    
    tab = 0xd0;
    p = fwrite(&tab , 1 , 1 ,Tracee); //
    
    tab = 0xCC ; // We stock in tab the trap code
    fwrite(&tab , 1 , 1 ,Tracee); //We write &tab in the process memory instead of the function address
    
    // fclose(Tracee);

    // On va definir deux paramètres de la fonction à executer
    int a = 1;
    int b = 1;

    modified_regs.rdi = a;
    modified_regs.rsi = b;
    modified_regs.rax = target_function_adresse;

    ptrace(PTRACE_SETREGS , tracee_pid , 0 , &modified_regs);
    //////////////////////////////////////////////////

    fseek(Tracee , function_adress, 0);
    // On continue le processus pour executer la fonction 
    ptrace(PTRACE_CONT , tracee_pid ,  NULL , NULL);
    waitpid(tracee_pid , &status , 0); 

    /// Maintenant on va récupèrer le résultat de la fonction  
    struct user_regs_struct modified_regs_2;
    ptrace(PTRACE_GETREGS , tracee_pid , 0 , &modified_regs_2);
    printf("La valeur renvoie pour l'exectution de la fonction est %lld \n " , modified_regs_2.rax);
    
    original_regs.rip = function_adress;

    // Point n°6 : Restauration de la valeur initiale des registres
    i = fseek(Tracee , function_adress, 0); // On se place au niveau de l'ancienne fonction
    if(i != 0){
        printf("fseek failed.");
        exit(-1);
    }
    fwrite(inst , 1 , 3 ,Tracee);
    // fwrite(&inst[1] , 1 , 1 ,Tracee);
    // fwrite(&inst[2] , 1 , 1 ,Tracee);   
    fclose(Tracee);

    ptrace(PTRACE_SETREGS , tracee_pid , 0 , &original_regs );

    getchar();

    // Redémarrage du processus 
    ptrace(PTRACE_DETACH , tracee_pid , NULL , NULL);


    return 0;
    }