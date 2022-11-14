#include<stdint.h>
#include<stdio.h>

#define IPv4 0x0800
#define IPv6 0x86DD
#define ARP 0x0806
#define TCP 6
#define UDP 17
typedef struct MAC_INFO_{
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t ether_type;
}MAC_INFO;

typedef struct IP_INFO_{
	uint8_t info[9];
	uint8_t protocol;
	uint16_t checksum;
	uint8_t source_addr[4];
	uint8_t dest_addr[4];
}IP_INFO;

typedef struct IPv6_INFO_{
	uint8_t info[6];
	uint8_t protocol;
	uint8_t hop_limit;
	uint16_t source_addr[8];
	uint16_t dest_addr[8];
}IPv6_INFO;
typedef struct TCP_INFO_{
	uint16_t source_port;
	uint16_t dest_port;
	uint8_t info[16];
}TCP_INFO;

typedef struct UDP_INFO_{
	uint16_t source_port;
	uint16_t dest_port;
	uint8_t info[16]; 
}UDP_INFO;

void print_mac(MAC_INFO mac);
uint8_t print_ip(IP_INFO ip);
uint8_t print_ipv6(IPv6_INFO ipv6);
void print_tcp(TCP_INFO tcp);
void print_udp(UDP_INFO udp);
void print_func(const u_char *packet,uint32_t total_len);
