CC=gcc
CFLAGS=-Wall

snifer: main.c 
	$(CC) $(CFLAGS) -o main  

clean: 
	rm main
