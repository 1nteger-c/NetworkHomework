#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

typedef struct irh
{
    u_int16_t buf;
    u_int16_t it_len;
} IRH;

typedef struct ih
{
    uint8_t subtype;
    uint8_t flags;
    uint16_t duration_id;
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint8_t bss_id[6];
} IH;

typedef struct beacon
{
    uint8_t bss_id[6];
    int beacons;
    char ess_id[256];
    uint8_t ess_id_flag = 0;
} BEACON;

BEACON beacon_array[100];
int array_size = 0;
void airodump(pcap_t *handle);

void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump wlan0\n");
}

void print_mac(uint8_t *mac_addr)
{
    for (int i = 0; i < 5; i++)
    {
        printf("%02X:", mac_addr[i]);
    }
    printf("%02X", mac_addr[5]);
}

void print_dump(void)
{
    printf("\033[H\033[J\n");
    puts("BSSID\t\t\tBeacons\t\tESSID");
    for (int i = 0; i < array_size; i++)
    {

        print_mac(beacon_array[i].bss_id);

        printf("\t\t%d\t", beacon_array[i].beacons);

        if (beacon_array[i].ess_id_flag)
        {
            printf("%s", beacon_array[i].ess_id);
        }
        printf("\n");
    }
}
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    airodump(handle);

    pcap_close(handle);

    return 0;
}

void airodump(pcap_t *handle)
{
    while (1)
    {
        print_dump();
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
        {
            continue;
        }
        if (res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        IRH *irh_hdr = (IRH *)packet;

        IH *ih_hdr = (IH *)(packet + irh_hdr->it_len);
        int hdr_len = irh_hdr->it_len + sizeof(IH) + 12;
        uint8_t *lan_data = (uint8_t *)(packet + hdr_len);

        if (ih_hdr->subtype == 0x80)
        {
            int flag = 0;
            for (int i = 0; i < array_size; i++)
            {
                if (!memcmp(beacon_array[i].bss_id, ih_hdr->bss_id, 6)) // if same bss_id
                {
                    flag = 1;
                    beacon_array[i].beacons += 1;
                    int caplen = header->caplen;
                    int cnt = hdr_len;
                    while (hdr_len < caplen)
                    {
                        int tmp = packet[cnt++];
                        int len = packet[cnt++];
                        if (cnt + len >= caplen)
                            break;
                        if (tmp == 0)
                        {
                            beacon_array[i].ess_id_flag = 1;
                            memcpy(beacon_array[i].ess_id, packet + cnt, len);
                        }
                    }
                }
            }
            if (!flag) // new bss_id
            {
                BEACON get;
                memcpy(get.bss_id, ih_hdr->bss_id, 6);
                get.beacons = 1;
                int caplen = header->caplen;
                int cnt = hdr_len;
                while (hdr_len < caplen)
                {
                    int tmp = packet[cnt++];
                    int len = packet[cnt++];
                    if (cnt + len >= caplen)
                        break;
                    if (tmp == 0)
                    {
                        get.ess_id_flag = 1;
                        memcpy(get.ess_id, packet + cnt, len);
                    }
                }
                memcpy(&beacon_array[array_size++], &get, sizeof(BEACON));
            }
        }
        print_dump();
    }
}