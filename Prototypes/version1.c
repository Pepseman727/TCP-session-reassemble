#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <time.h>

#include <pcap.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <inttypes.h>

#define PCAP_BUF_SIZE 2048
#define SESSION_COUNT 5


int synCount[PCAP_BUF_SIZE];
int synIdx = 0;
char synIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];

typedef struct {
	const struct ip* headerIP;
	const struct tcphdr* headerTCP;
	u_char* data;

} tcpSegment;

typedef struct {
	char IPaddr1;
	char IPaddr2;
	u_int TCPport1;
	u_int TCPport2;
	//Payload
	tcpSegment packets[12];

} session;


session sessionsTCP[SESSION_COUNT];


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv) {

	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i, maxCountSyn = 0, maxIdxSyn = 0;

	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return -1;
	}

	fp = pcap_open_offline(argv[1], errbuf);
	if (fp == NULL) {
		fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
		return 0;
	}

	if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
		fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
		return 0;
	}

	for (i = 0; i < synIdx; ++i) {
		if (maxCountSyn < synCount[i]) {
			maxCountSyn = synCount[i];
			maxIdxSyn = i;
		}
	}

	pcap_close(fp);
	return 0;

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	char sourceIP[INET_ADDRSTRLEN];
	char destIP[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
	u_char* data;
	int dataLength = 0;
	int i;
	uint32_t tcpSeq = 0;
	uint32_t tcpAck = 0;

	ethernetHeader = (struct ether_header*)packet;

	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {

		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

		if (ipHeader->ip_p == IPPROTO_TCP) {
			//You must find all packets with current src and dest IP with fixed port
			tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);



			data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			tcpSeq = ntohl(tcpHeader->th_seq);
			tcpAck = ntohl(tcpHeader->th_ack);
			if (tcpHeader->th_flags & TH_SYN) {
				printf("%.2x %s   ---->   %s\n\tSeq num: %"PRIu32"\n\tAck num: %"PRIu32"\n", 
					tcpHeader-> th_flags, sourceIP, destIP,tcpSeq,tcpAck);
				printf("\tTime: %d.%06d\n\n",(int) pkthdr->ts.tv_sec, (int) pkthdr->ts.tv_usec);
			}
				
		/*	if (tcpHeader->th_flags & TH_SYN) {
				for (i = 0; i < synIdx; ++i) {
					if (strcmp(sourceIP,synIP[i]) == 0) {
						synCount[i] += 1;
					}
				}

				strcpy(synIP[synIdx], sourceIP);
				synCount[synIdx] = 1;
				synIdx += 1;

			}*/
		}
	}
}
