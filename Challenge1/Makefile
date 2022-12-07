# Makefile for:
#	TP SEL Challenge 1
#	Léo Laffeach and Lounès Meddahi
#============================================
CC = gcc
CFLAGS = -g

TARGET = Challenge1

ALL = Tracee $(TARGET)

#============================================
.PHONY: clean
all: Tracee $(TARGET)

Tracee: Tracee.c
	$(CC) $(CFLAGS) -static -o Tracee Tracee.c

$(TARGET): $(TARGET).c 
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c ../utilities.c

clean:
	$(RM) $(ALL)

#============================================
# Test
TIME = 5s

Challenge1_Test_soustraction:
	gnome-terminal -- ./Tracee;
	sleep $(TIME);
	./Challenge1 Tracee soustraction
	

Challenge1_Test_somme:
	gnome-terminal -- ./Tracee;
	sleep $(TIME);
	./Challenge1 Tracee somme
