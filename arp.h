#ifndef _ARPH
#define _ARPH
#include <stdio.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <net/ethernet.h>
#define GATEWAY_LEN 256
#define MAC_LEN 100
/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1   /* ARP Request              */
#define ARP_REPLY 2     /* ARP Reply               */

typedef struct pthreadargv {
  char *ip;
  pcap_t *handle;
} pthread_argv;

typedef struct arphdr {
    u_int16_t htype;    // Hardware Type
    u_int16_t ptype;    // Protocol Type
    u_char hlen;        // Hardware Address Length
    u_char plen;        // Protocol Address Length
    u_int16_t oper;     // Operation Code
    u_char sha[6];      // Sender hardware address
    u_char spa[4];      // Sender IP address
    u_char tha[6];      // Target hardware address
    u_char tpa[4];      // Target IP address
}arphdr_t;


void GetGateway(char* line[]);
void* arp_spoof_main(void*);
#endif
