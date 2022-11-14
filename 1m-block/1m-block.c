#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
int filter_flag;
char **bad_hosts;
int host_length;
int convert_string(const void *a, const void *b)
{
	return (strcmp(*(char **)a, *(char **)b));
}

void dump(unsigned char *buf, int size)
{
	int i;
	for (i = 0; i < size; i++)
	{
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}
void filter(unsigned char *data)
{
	unsigned char ip_front = data[0];
	int version = (ip_front >> 4);
	int length = (ip_front & 0xf) * 4;
	if (version != 4)
		return;
	unsigned char *http_packet = data + length + 20;
	unsigned char *host = NULL;
	for (int i = 16; i < 40; i++)
	{

		if (!strncmp(http_packet + i, "Host: ", 6))
		{

			host = http_packet + i + 6;
		}
	}
	if (host == NULL)
	{
		return;
	}

	for (int i = 0;; i++)
	{
		if (*(host + i) < '\x20')
		{
			*(host + i) = '\x00';
			break;
		}
	}
	//find string
	int start = 0;
	int finish = host_length - 1;
	int mid;
	int num;

	while (1)
	{
		mid = (start + finish) / 2;
		if (start > finish)
		{
			return;
		}
		num = strncmp(host, *(bad_hosts + mid), strlen(host));
		if (num > 0)
		{
			start = mid + 1;
		}

		else if (num == 0)
		{
			filter_flag = 1;
			printf("Something filtered!!!\n");
			printf("host : %s\n\n", host);
			printf("Something filtered!!!\n");
			printf("host : %s\n\n", host);
			return;
		}
		else
		{
			finish = mid - 1;
		}
	}
}
/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			   ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph)
	{
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
	{
		printf("payload_len=%d ", ret);
		filter(data);
	}
	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			  struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (filter_flag == 1)
	{

		filter_flag = 0;
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));
	if (argv[1] == NULL)
	{
		printf("Input error . INPUT : ./1m-block [file_name]\n");
		return -1;
	}
	FILE *fp = fopen(argv[1], "r");
	char input_str[30];
	char *ptr;
	int len;
	int max = 0;

	bad_hosts = (char **)malloc(1000000 * sizeof(char *));
	for (int i = 0; i < 1000000; i++)
	{
		fscanf(fp, "%s", input_str);
		ptr = strtok(input_str, ",");
		ptr = strtok(NULL, ",");
		if (ptr == NULL)
		{
			host_length = i;
			break;
		}

		len = strlen(ptr);
		if (max < len)
			max = len;
		*(bad_hosts + i) = (char *)malloc(len + 1);
		strcpy(*(bad_hosts + i), ptr);
	}
	qsort(bad_hosts, host_length, sizeof(bad_hosts[0]), convert_string);
	//file sort

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
