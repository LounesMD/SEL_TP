# Makefile for:
#	TP SEL
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
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c utilities.c

clean:
	$(RM) $(ALL)

#============================================
# Test

Challenge1_Test_soustraction:
	./Challenge1 Tracee soustraction

Challenge1_Test_somme:
	./Challenge1 Tracee somme
