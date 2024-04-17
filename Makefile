CC=gcc
LIBS=-lpcap

all: arp-spoof

arp-spoof: main.o
	$(CC) -o arp-spoof main.o $(LIBS)

main.o: main.c
	$(CC) -c main.c

clean:
	rm -f arp-spoof *.o

