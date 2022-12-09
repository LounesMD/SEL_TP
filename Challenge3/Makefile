# Makefile for:
#	TP SEL Challenge 3
#	Léo Laffeach and Lounès Meddahi
#============================================
CC = gcc
CFLAGS = -g

TARGET = Challenge3

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
Get_Hexa_Somme:
	objdump -d Interm

#============================================
# Test
TIME = 5s

Challenge3_Test:
	gnome-terminal -- ./Tracee;
	sleep $(TIME);
	./Challenge3 Tracee somme
