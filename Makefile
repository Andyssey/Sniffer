CC=gcc
CFLAGS= -std=gnu99
LDFLAGS= -lpcap

snifer: main.c 
	$(CC) $(CFLAGS) -w -o main main.c  $(LDFLAGS) 

clean: 
	rm main
