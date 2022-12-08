# M1 - TP SEL 
This repository belongs to **<a href="https://github.com/Leo-Laffeach" target="_blank">Léo Laffeach</a>** and **<a href="https://github.com/LounesMD" target="_blank">Lounès Meddahi</a>**. <br>
In this repository you find the 3 challenges we have taken up and their explanation.

## Utilities
`utilities.c` is a file with four functions to help with getting the pid or the function address with only the name of the process or the function.

- `command_writer`: 
	concatenate the command_part into command
- `get_pid`:
        get the pid of a process given his name, using pgrep command
- `find_addr_fun`:
        return the address of a function in a process given the name of the process and the function
- `function_offset`:
        return the address of a function in a process given his pid and the function name.

## Challenge 1 (*Validated*):
The code for the first challenge is in the folder `./Challenge1` and can be compiled by doing `make` in a terminal in ./Challenge1.

To test it, there is (If you use gnome terminal) :

    make Challenge1_Test_soustraction
    make Challenge1_Test_somme

Else do

    ./Tracee
    
and after some time do

    ./Challenge1 Tracee soustraction
    ./Challenge1 Tracee somme

The function `soustraction` is call after a long time, so it does not do anything. While `somme` is call at each iteration so the process will be "killed" with Challenge1_Test_somme because of the trap.

## Challenge 2 (*Validated*):
The code for the second challenge is in the folder `./Challenge2` and can be compiled by doing `make` in a terminal in ./Challenge2. <br>
The aim of this challenge is to execute a function instead of another one in the traced process. In our case, we will execute `toto : x,y -> 2*(x+y)` instead of `somme : x,y -> x+y`.

To test it, there is (If you use gnome terminal) :

    make Challenge2_Test
    
   > [toto(1, 2)] return [6]

Else do

    ./Tracee
    
and after some time do

    ./Challenge2 Tracee somme toto -arg1 5 -arg2 3
    
   > [toto(5, 3)] return [16]
    
you can play with -arg1 and -arg2

Then, after the execution of `toto` instead of `somme`, the traced process resumes its execution with the function `somme`.

## Challenge 3 (*Not validated*):

The code for the third challenge is in the folder `./Challenge3` and can be compiled by doing `make` in a terminal in ./Challenge3.

To test it, there is (If you use gnome terminal) :

    make Challenge3_Test

Else do

    ./Tracee
    
and after some time, do

    ./Challenge3 Tracee somme 24


It does not work and we think that we know why. When you run the above commands, the traced process, Tracee, executes a trap after the execution of `posix_memalign` `mprotect` instead of resuming its initial execution. The reason is because when we write the first trap, then we execute `posix_memalign` and `mprotect` and finally we restaure the overwritten instruction by the trap. However, the process executes the loop again and executes the trap instead of the restored instruction.

## Project structure
Our project has the following structure :

```
.
├── Challenge1
│   ├── Challenge1.c
│   ├── Makefile
│   └── Tracee.c
├── Challenge2
│   ├── Challenge2.c
│   ├── Makefile
│   └── Tracee.c
├── Challenge3
│   ├── Challenge3.c
│   ├── Interm.c
│   ├── Makefile
│   └── Tracee.c
├── README.md
├── utilities.c
└── utilities.h

3 directories, 13 files
```
