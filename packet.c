#include <pcap/pcap.h>
#include "packet.h"
#include "arp.h"

#define ETHER_HEAD_LEN 14

extern int GetMacflag;
extern arphdr_t arp_attack_packet;
extern struct sniff_ethernet et_attack_packet;

// sniff handler
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, char* ip)
{
	struct sniff_ethernet *eth = (struct sniff_ethernet *)packet;
	eth->ether_type = ntohs(eth->ether_type);

	if (eth->ether_type != 0x806) return;

	arphdr_t* arpheader = (struct arphdr_t *)(packet + ETHER_HEAD_LEN); /* Point to the ARP header */
	arpheader->htype = ntohs(arpheader->htype);
	arpheader->ptype = ntohs(arpheader->ptype);
	arpheader->oper = ntohs(arpheader->oper);

	char saddr[16];
	sprintf(saddr, "%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);
	//printf("target ip: %s, packet get ip: %s \n", ip, saddr);
	//printf("len: %d, packet len: %d \n", strlen(ip), strlen(saddr));
	//not filter
	if(strcmp(saddr,ip))
	{
		return;
	}

	printf("\n\nReceived Packet Size: %d bytes\n", header->len);
	printf("Hardware type: %s\n", (arpheader->htype == 1) ? "Ethernet" : "Unknown");
	printf("Protocol type: %s\n", (arpheader->ptype == 0x0800) ? "IPv4" : "Unknown");
	printf("Operation: %s\n", (arpheader->oper == ARP_REQUEST)? "ARP Request" : "ARP Reply");

	GetMacflag = 1;
 	/* If is Ethernet and IPv4, print packet contents */
	if (arpheader->htype == 1 && arpheader->ptype == 0x0800)
	{
		int i;
		printf("Sender MAC: ");
	    for(i=0; i<6;i++)
	    {
	        printf("%02X:", arpheader->sha[i]);
	        et_attack_packet.ether_dhost[i] = arpheader->sha[i];
	    }

	    printf("\nSender IP: ");
	    for(i=0; i<4;i++)
	        printf("%d.", arpheader->spa[i]);

	    printf("\nTarget MAC: ");
	    for(i=0; i<6;i++)
	    {
	        printf("%02X:", arpheader->tha[i]);
	    }

	    printf("\nTarget IP: ");
	    for(i=0; i<4; i++)
	        printf("%d.", arpheader->tpa[i]);

    	printf("\n");
	}
}

//sniff main
void* packet_sniffer_main(void* arg)
{
	//pcap_t* handle;
	struct bpf_program filter;
	char* dev, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask=0;
	/* [stage1] packet capture callback function*/
	pthread_argv *pargv = (pthread_argv *)arg; 
	pcap_t *handle = (pcap_t *)pargv->handle;

	struct pcap_pkthdr *header;
	const unsigned char *packet;

	while(1) {
		int ret = pcap_next_ex(handle, &header, &packet);
		if (ret == 0) continue;
		else if (ret < 0) {
			printf("[*] Couldn't receive packets\n");
			return -1;
		}

		packet_handler(NULL, header, packet, pargv->ip);
	}

	pcap_close(handle);
	return NULL;
}
