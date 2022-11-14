#include<stdio.h>
#include<string.h>
#include<netinet/in.h>
#include "pcap_test.h"
void print_mac(MAC_INFO mac){
	printf("Destination MAC Address : ");
	for(int i=0;i<6;i++){
		printf("%02x",mac.dest_mac[i]);
		if(i<5)
			printf(":");
	}
	printf("\n");
	printf("Source MAC Address : ");
	for(int i=0;i<6;i++){
		printf("%02x",mac.src_mac[i]);
		if(i<5)
			printf(":");
	}
	printf("\n");
}

uint8_t print_ip(IP_INFO ip){
	printf("Source IP Adrress : ");
	for(int i=0;i<4;i++){
		printf("%d",ip.source_addr[i]);
		if(i<3)
			printf(".");
	}
	printf("\n");
	printf("Destination IP Address : ");
	for(int i=0;i<4;i++){
		printf("%d",ip.dest_addr[i]);
		if(i<3)
			printf(".");
	}
	printf("\n");
	return ip.protocol;
}
uint8_t print_ipv6(IPv6_INFO ipv6){
        printf("Source IPv6 Adrress : ");
        for(int i=0;i<8;i++){
                printf("%x",ntohs(ipv6.source_addr[i]));
                if(i<7)
                        printf(":");
        }
        printf("\n");
        printf("Destination IPv6 Address : ");
        for(int i=0;i<8;i++){
                printf("%x",ntohs(ipv6.dest_addr[i]));
                if(i<7)
                        printf(":");
        }
        printf("\n");
        return ipv6.protocol;
}


void print_tcp(TCP_INFO tcp){
	printf("Source Port : %u\n",ntohs(tcp.source_port));
	printf("Destination port : %u\n",ntohs(tcp.dest_port));
}
void print_udp(UDP_INFO udp){
        printf("Source Port : %u\n",ntohs(udp.source_port));
        printf("Destination port : %u\n",ntohs(udp.dest_port));
}

void print_func(const u_char *packet,uint32_t total_len){
//Ethernet INFO
	MAC_INFO mac;
	int len = 0;
	memcpy(&mac,packet,sizeof(MAC_INFO));
	len += sizeof(MAC_INFO);
	uint8_t protocol;
	IP_INFO ip_check;
	memcpy(&ip_check,packet+len,sizeof(IP_INFO));
	if(ntohs(mac.ether_type) != IPv4){
	printf("ERROR!! It is not IPv4\n");
	return ;
	}
	if (ip_check.protocol != TCP){
	printf("ERROR!! It is not TCP\n");
	return ;
	}
	print_mac(mac);
//IP INFO
	switch(ntohs(mac.ether_type)){
	case IPv4:
		IP_INFO ip;
		memcpy(&ip,packet + len,sizeof(IP_INFO));
		len += sizeof(IP_INFO);
		protocol = print_ip(ip);
		break;
/*
	case IPv6:
		IPv6_INFO ipv6;
		memcpy(&ipv6,packet + len,sizeof(IPv6_INFO));
		len += sizeof(IPv6_INFO);
		protocol = print_ipv6(ipv6);
		break;
*/

	default:
		 printf("ERROR : BAD ether_type%d\n",ntohs(mac.ether_type));
		 return ;
	}
//TCP INFO
	switch(protocol){
	case TCP:
		TCP_INFO tcp;
		memcpy(&tcp,packet + len,sizeof(tcp));
		len += sizeof(tcp);
		print_tcp(tcp);
		break;
/*
        case UDP:
                UDP_INFO udp;
                memcpy(&udp,packet + len,sizeof(udp));
                len += sizeof(udp);
                print_udp(udp);
                break;
*/
	default:
		printf("ERRPR : BAD PROTOCOL %d\n",protocol);
		return ;
	}
//HTTP INFO
	uint8_t data[16];
	int data_len = (total_len - len < 16) ? total_len - len : 16;
	memcpy(&data,packet + len,data_len);
	printf("DATA :");
	for(int i=0;i<data_len;i++){
		printf("%02x ",data[i]);
	}
	printf("\n\n");
}


