CC = gcc
OBJS = main.o arp.o packet.o
TARGET = arpspoof

arpspoof: main.o arp.o packet.o
	gcc main.o arp.o packet.o -o arpspoof -lpcap -pthread

main.o: main.c packet.h
	gcc main.c -c -o main.o -lpcap

arp.o: arp.c arp.h
	gcc arp.c -c -o arp.o
	
packet.o: packet.c packet.h
	gcc packet.c -c -o packet.o -lpcap

clean:
	rm -f $(OBJS) $(TARGET)