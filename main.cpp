#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <malloc.h>

#include <pcap.h>

/*#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
*/
#include <inttypes.h>

#define PCAP_BUF_SIZE 2048


//TO DO: Think about names
typedef struct {
	struct pcap_pkthdr pktHeader;
	u_char* pktData;

} tcpSegment;

tcpSegment* segments;

typedef struct {
	char IPaddr1;
	char IPaddr2;
	u_int TCPport1;
	u_int TCPport2;
	//Payload
	tcpSegment packets[12];

} flowTCP; //Think about name of structure

int countOfTcp(const char* fileName);

int main(int argc, char** argv) {
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	u_int i = 0;
	int state;
	u_char* dataCopy;
	u_char* data;
	int tcpCount = countOfTcp(argv[1]);
	
	segments = (tcpSegment*)malloc(sizeof(tcpSegment) * tcpCount);
	
	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader; 

	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return -1;
	}


	if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}
	
	while((state = pcap_next_ex(fp, &pkt_header, &pkt_data)) >= 0) {
		ethernetHeader = (struct ether_header*)pkt_data;
		if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
			ipHeader = (struct ip*)(pkt_data + sizeof(struct ether_header));
			if (ipHeader->ip_p == IPPROTO_TCP) {
				dataCopy  = (u_char*)malloc(pkt_header->caplen * sizeof(pkt_data));
				segments[i].pktHeader = *pkt_header;
				memcpy(dataCopy, pkt_data, segments[i].pktHeader.caplen * sizeof(pkt_data));
				segments[i].pktData = dataCopy;
				++i;
			}
		}
	}

	free(dataCopy);
	
	for (i = 0; i < tcpCount; ++i) {
		tcpHeader = (struct tcphdr*)(segments[i].pktData + sizeof(struct ether_header) + sizeof(struct ip));
		printf("TCP PACKET %d.\n\tHIM TCP FLAG: %d\n\n",i,tcpHeader->th_flags);
	}


	if (state == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}

	free(segments);
	pcap_close(fp);
	return 0;

}

int countOfTcp(const char* fileName) {
	pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int state;
	int tcpCount = 0;

	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;

	if ((fp = pcap_open_offline(fileName, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s.\n", fileName);
		return -1;
	}

	while((state = pcap_next_ex(fp, &pkt_header, &pkt_data)) >= 0) {
		ethernetHeader = (struct ether_header*)pkt_data;
		ipHeader = (struct ip*)(pkt_data + sizeof(struct ether_header));
		if (ipHeader->ip_p == IPPROTO_TCP) ++tcpCount;
	}

	pcap_close(fp);
	return tcpCount;

}
