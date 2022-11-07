#include<stdio.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>

// Le but du challenge 1 est de fare


// trap = arreté un processus et lever une exception 
// ptrcace_attach =  On va utiliser ça pour attacher un processus tracer à un tracee
// ptrace_detach = Restart le tracee arreté
// ptrace_cont = Restart le tracee arreté mais en se détachant de lui


// 1) Il nous faut un processus père (tracer)
// 2) Il nous faut un processus fils (tracee)
// 3) Le père execute PTRACE_ATTACH pour s'attacher au fils (   )
// 4) Le père envoie un signal au fils en utilisant 
// 5) Le père -> déclanche TRAP si le fils execute une fonction dont le nom est passé en paramètre
//            -> PTRACE_DETACH sinon

int somme(int a , int b){
    return a+b;
}

int soustraction(int a , int b){
    return a-b;
}
// Ce programme est celui qui sera tracé 
int main( int argc , char * argv[]){
    printf("\nChild Process ID is %d \n",getpid());

    for(int i = 0 ; i<100000 ; i++){
        sleep(2);
        printf("%d - %d \n",i,getpid());
        somme(1 , 1);
    }
    soustraction(1 , 1);
    return 0 ;    
}
