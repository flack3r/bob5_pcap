#include <stdio.h>
#include <pcap.h>
#include "packet.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//sniff packet
	#define SIZE_ETHERNET 14
	const struct sniff_ethernet* ethernet;
	const struct sniff_ip* ip;
	const struct sniff_tcp* tcp;
	const u_char* payload;

	u_int size_ip;
	u_int size_tcp;

	printf("Jacked a packet with length of [%d]\n", header->len);
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20)
	{
		printf("Invalid IP headerl ength: %u bytes\n", size_ip);
		exit(-1);
	}

	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			break;
		default:
			return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if(size_tcp < 20)
	{
		printf("Invalid TCP header length: %u bytes\n", size_tcp);
		exit(-1);
	}

	printf("[*]====Print Info==== \n");
	printf("[-]eth.smac: %s\n",ether_ntoa(ethernet->ether_shost));
	printf("[-]eth.dmac: %s\n",ether_ntoa(ethernet->ether_dhost));
	printf("[-]ip.sip: %s\n", inet_ntoa(ip->ip_src));
	printf("[-]ip.dip: %s\n", inet_ntoa(ip->ip_dst));
	printf("[-]tcp.sport: %d\n", ntohs(tcp->th_sport));
	printf("[-]tcp.dport: %d\n", ntohs(tcp->th_dport));
	printf("\n");
}

int main(int argc, char* argv[])
{
	pcap_t* handle;
	char* dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);

	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return -1;
	}
	printf("Device: %s\n", dev);
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if( pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return -1;
	}

	pcap_loop(handle, 0, packet_handler, NULL);
	pcap_close(handle);

	return 0;
	
}
