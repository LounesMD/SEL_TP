# Makefile for:
#	TP SEL Challenge 2
#	Léo Laffeach and Lounès Meddahi
#============================================
CC = gcc
CFLAGS = -g

TARGET = Challenge2

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
ARG1 = 1
ARG2 = 2
TIME = 5s

Challenge2_Test:
	gnome-terminal -- ./Tracee;
	sleep $(TIME);
	./Challenge2 Tracee somme toto -arg1 $(ARG1) -arg2 $(ARG2)
