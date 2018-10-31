#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <libnet/include/libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define HOST_STR_LEN 6 //"Host: " length == 6

char *bad_host; // defines in argument

/* returns packet id */
void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
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
		{printf("payload_len=%d ", ret); /*dump(data,ret);*/}

	fputc('\n', stdout);

	return id;
}

void lps_array(const char* pattern, int *lps)
{
	int i = 1;
	int len = 0;
	int p_size = strlen(pattern);

	lps[0] = 0;

	while(i < p_size)
	{
		if(pattern[i] == pattern[len])
		{
			len++; i++;
			lps[i] = len ;
		}
		else
		{
			if(len != 0)  len = lps[len-1];
			else {lps[i] = 0; i++;}	
		}
	} 
}

int kmp(char* str, const char* pattern)
{
	int s_size = strlen(str);
	int p_size = strlen(pattern);

	int *lps = (int*)malloc(p_size * sizeof(int));
	int i = 0, j = 0;

	lps_array(pattern,lps);

	while(i < s_size)
	{
		if(pattern[j] == str[i]) { j++; i++; }
		if(j == p_size) { free(lps); return (i-j);}
		else if (pattern[j] != str [i])
		{
			if( j != 0 ) j = lps[j-1];
			else i++;
		}
	}
	free(lps);
	return 0;
}


int host_blocked(struct nfq_q_handle *qh,  struct nfq_data *tb, u_int32_t id) 
{
	uint8_t *data;
	uint8_t *body;
	uint8_t *host;
	struct libnet_ipv4_hdr *iph;
	struct libnet_tcp_hdr *tcph;
	int ip_len;
	int tcp_len;
	int idx = 0;

	const char* http_method[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
	const char* str_host = "Host: ";

	int res = nfq_get_payload(tb, &data);
	if(res < 0) {perror("nfq_get_payload: "); return -1;}

	iph = (struct libnet_ipv4_hdr *)data;

	if(iph->ip_p != IPPROTO_TCP) return 0;
	ip_len = iph->ip_hl*4;
	tcph = (struct libnet_tcp_hdr *)(data + ip_len);

	if(tcph != NULL)
	{
		tcp_len = tcph->th_off*4;
		body = (uint8_t *)(data + ip_len + tcp_len); // get data body 
		for(int i = 0; i < 6; i++)
		{
			if(strncmp((const char*)body,http_method[i],strlen(http_method[i])) == 0)
			{
				if(idx = kmp((char *)body, str_host))
				{
					idx = idx + HOST_STR_LEN; // move idx to host, "Host: " length == 6 
					host = (uint8_t *)(body + idx);
					if(strncmp((char*)host,bad_host,strlen(bad_host)) == 0)
						{printf("[Drop Bad Host]: %s\n", bad_host ); return 1; }
				}
			}
		}
	}
	
	return 0;
}	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");

	if(host_blocked(qh,nfa,id) == 1)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
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
	char buf[4096] __attribute__ ((aligned));

    bad_host = argv[2];
    
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
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
		if (rv < 0 && errno == ENOBUFS) {
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

