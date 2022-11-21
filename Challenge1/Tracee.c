#include<stdio.h>
#include<sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <stdio.h>

int somme(int a , int b){
    return a+b;
}

int soustraction(int a , int b){
    return a-b;
}

int main( int argc , char * argv[]){
    for(int i = 0 ; i<100000 ; i++){
        sleep(2);
        printf("%d - %d \n",i,getpid());
        somme(1 , 1);
    }
    soustraction(1 , 1);
    return 0 ;    
}
