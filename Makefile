CC=gcc
CFLAGS= -std=gnu99
LDFLAGS= -lpcap

snifer: main.c cli.c 
	$(CC) $(CFLAGS) -w -o main main.c  $(LDFLAGS) 
	$(CC) $(CFLAGS) -w -o cli cli.c $(LDFLAGS) 

clean: 
	rm main
