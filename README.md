# M1 - TP SEL 
Made by Léo Laffeach and Lounès Meddahi

### utilities
    utilities.c is a file with four functions to help with getting the pid or the function address with only the name of the process or the function.

## Challenge 1:
    The code for the first challenge is in the folder Challenge1

    It can be compiled by doing `make` in a terminal in Challenge1.

    To test it, there is:
        (If you use gnome terminal)
            make Challenge1_Test_soustraction
            make Challenge1_Test_somme
    
        Else do
            ./Tracee 
        and after some time do
	        ./Challenge1 Tracee soustraction
        or
            ./Challenge1 Tracee somme

    soustraction is call after a long time, so it does not do anything, while somme is call at each iteration so the process will be "killed" with Challenge1_Test_somme because of the trap.

## Challenge 2:
    The code for the second challenge is in the folder Challenge2
    
    It can be compiled by doing `make` in a terminal in Challenge2.

    To test it, there is:
        (If you use gnome terminal)
            make Challenge2_Test
        [toto(1, 2)] return [6]
    
        Else do
            ./Tracee
        and after some time do
            ./Challenge2 Tracee somme toto -arg1 5 -arg2 3
        [toto(5, 3)] return [16]
        you can play with -arg1 and -arg2
    
    toto(x, y) = 2*(x + y)
    We trap Tracee and make it execute toto with our parameter where Tracee should have execute somme.
    After that, Tracee keep going by executing somme.

## Challenge 3
    The code for the third challenge is in the folder Challenge3

    It can be compiled by doing `make` in a terminal in Challenge3.

    To test it, there is:
        (If you use gnome terminal)
            make Challenge3_Test
    
        Else do
            ./Tracee
        and after some time, do
            ./Challenge3 Tracee somme


    It does not really work for now.

