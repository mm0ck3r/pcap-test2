#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

void print_mac(uint8_t* addr){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void data_print(uint8_t* data, int dLen){
	if (dLen <= 0) printf("None");
	else{
		if(dLen > 20) dLen = 20;
		for (int i=0; i<dLen; i++){
			printf("%02x ", *data);
			data++;
		}
	}
}

void printUsage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		printUsage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
    if (!parse(&param, argc, argv)) return -1;

	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("captured: %u bytes\n", header->caplen);

		struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr *)packet;
		if(ntohs(ethernet->ether_type) != ETHERTYPE_IP) continue;

		struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) (packet + sizeof(*ethernet));
		if(ipv4->ip_p != IPPROTO_TCP) continue;

		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (packet + sizeof(*ethernet) + sizeof(*ipv4));

		uint8_t *data = (uint8_t*)(packet + sizeof(*ethernet) + sizeof(*ipv4) + sizeof(*tcp));
		int dLen = (int)(header->caplen) - (sizeof(*ethernet) + sizeof(*ipv4) + sizeof(*tcp));

		printf("[ MAC ] ");
		print_mac(ethernet->ether_shost);
		printf(" -> ");
		print_mac(ethernet->ether_dhost);

		printf("\n[ IP ] ");
		printf("%s:%u", inet_ntoa(ipv4->ip_src),ntohs(tcp->th_sport));
		printf(" -> ");
		printf("%s:%u", inet_ntoa(ipv4->ip_dst),ntohs(tcp->th_dport));

		/* 데이터 출력 */
		printf("\n[ DATA ] ");
		data_print(data, dLen);


		printf("\n=====================================================\n\n");
	}

	pcap_close(pcap);
}
