#include <stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<string.h>
#include <sys/types.h>
#include <sys/wait.h>


//Ce main va servir afin de tracer un processus
// Il y'a aura 3 paramètres 1° l'execution du fichier 2° Le nom de la fonction 3° Le pid du processus à tracer 
int main(int argc, char *argv[]){
    pid_t tracee_pid;
    char *  endPtr;
    char *  endPtr2;    
    long long function_adress;
    

    if(argc != 3){
        printf("Pas assez de paramètre ");
        exit(1);
    }
    
    function_adress = strtoll( argv[1] , &endPtr2 , 16); // On récupère l'adresse de la fonction (version simplifiée) 
    printf("adresse de la function : %lld \n ", function_adress);

    tracee_pid = strtoll( argv[2] , &endPtr, 10); // On récupère le Process IDentifier (PID)

    int status;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL); // Ici on s'attache au processus associé au pid donné
    waitpid(tracee_pid , &status , 0);


    // Récupèrer le pid grâce à pgrep
    // /!\ Je devrais vérifier que le pid existe avant de m'y attache ? /!\ 
    // On utilise pgrep pour pouvoir vérifier que le pid est bien existant.

    // Ce qu'il faut faire maintenant :
    // 1) Récupérons la listes des adresses des fonctions de tracee_pid
    // 2) Vérifier que function_adresse si trouve 
    // 3) Si non on se détache du processus et on le relance : ptrace(PTRACE_DETACH , tracee_pid)
    // 4) Si oui on fait : 
    // 4.1) On retrouve où commence function_adress
    // 4.2) On réécrit trap à la place (0xCC)
    // 4.3) On se détache : ptrace(PTRACE_DETACH , tracee_pid)

    ////////////////////////////////////////////////////////

    // 1) Récupérons la listes des adresses des fonctions de tracee_pid

    // /!\ attention de compiler en static le tracee
    char buffer[20];
    snprintf(buffer, 20, "/proc/%d/mem",tracee_pid);
    FILE * Tracee = fopen( buffer , "wb"); // Là on récupere toutes les fonctions dans le processus
    if(Tracee == NULL){
        printf("Tracee pas ouvert \n");
        exit(-1);
    }

    // Maintenant il nous faut un la tête de lecture à l'adresse de la fonction +1 ? et ajouter 0xCC

    // Il faut qu'on mette le pointeur sur l'adresse de la fonction ??? Puis qu'on fasse une modification pour ajouter 0XCC
    int i;
    i = fseek(Tracee , function_adress , 0); // Je dois mettre à la place de ? la position de la fonction recherchée 
    if(i != 0){
        printf("Le fseek n'a pas fonctionnait. ");
        exit(-1);
    }
    char tab = 0xCC ;

    int p;
    p = fwrite(&tab , 1 , 1 ,Tracee); //On va écrire &tab dans buffer au bonne endroit car on va être bien placé grâce à fseek
    printf("p = %d ",p);
    fclose(Tracee);
    getchar();

    ptrace(PTRACE_DETACH , tracee_pid, NULL, NULL);     // On a besoin que d'un octet
    waitpid(tracee_pid , &status , 0);


     // Là on relance le processus au quel on s'est attaché en le lachant
    return 0;
    }


    // Les adresses :
    // Somme : 0000000000401cb5
    // Soustraction : 0000000000401ccd