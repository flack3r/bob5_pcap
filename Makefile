CC = gcc
OBJS = packet.o
TARGET = packet
packet : packet.o
	gcc -o packet packet.o -l pcap

packet.o : packet.c packet.h
	gcc packet.c -c -o packet.o -lpcap

clean:
	rm -f $(OBJS) $(TARGET)