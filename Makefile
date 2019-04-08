CC=gcc
LDFLAGS= -lpcap

snifer: main.c 
	$(CC) -w -o main main.c  $(LDFLAGS) 

clean: 
	rm main
