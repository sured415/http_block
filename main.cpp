#include <iostream>
#include <stdint.h>
#include <string>					//std::string
#include <regex>					//std::regex
#include <set>
#include <fstream>
#include "win32\libnet.h"
#include "pcap.h"

using namespace std;

pcap_if_t *d;
set<string> ban_list;
string waring_http; //"HTTP/1.1 302 Found" "Connection: close" "Content - Type : text / html; charset = UTF - 8", "Content - Length: 0\nLocation : http ://warning.or.kr/i1.html";
regex check("Host: ([^\r]*)");

#pragma pack(push, 1)
struct res_packet {
	struct libnet_ethernet_hdr res_ethH;
	struct libnet_ipv4_hdr res_ipH;
	struct libnet_tcp_hdr res_tcpH;
	char s[152] = "HTTP/1.1 302 Found\r\nConnection: close\r\nContent - Type : text / html; charset = UTF - 8\r\nContent - Length: 0\r\nLocation : http ://warning.or.kr/i1.html\r\n";
}r;
#pragma(pop)

int get_dev() {
	int inum;
	pcap_if_t *alldevs = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];

	int offset = 0;

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}
	// print them
	int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	return 0;
}

int check_host(const u_char* packet) {
	string s_data, check_host;
	s_data = (char*)packet;
	smatch host;

	if (regex_search(s_data, host, check)) {
		check_host = host[1];
		set<string>::iterator iter;
		iter = ban_list.find(check_host);
		if (iter != ban_list.end()) {
			return 1;
		}
	}
	return 0;
}

int make_res_packet(libnet_ethernet_hdr* ethH, struct libnet_ipv4_hdr* ipH, struct libnet_tcp_hdr* tcpH, uint32_t http_len) {
	
	memcpy(r.res_ethH.ether_shost, ethH->ether_dhost, sizeof(r.res_ethH.ether_shost));
	memcpy(r.res_ethH.ether_dhost, ethH->ether_shost, sizeof(r.res_ethH.ether_dhost));
	r.res_ethH.ether_type = ntohs(ETHERTYPE_IP);

	r.res_ipH = *ipH;
	r.res_ipH.ip_src = ipH->ip_dst;
	r.res_ipH.ip_dst = ipH->ip_src;
	r.res_ipH.ip_tos = 0x01;
	r.res_ipH.ip_len = ntohs(191);

	r.res_tcpH = *tcpH;
	r.res_tcpH.th_sport = tcpH->th_dport;
	r.res_tcpH.th_dport = tcpH->th_sport;
	r.res_tcpH.th_seq = tcpH->th_ack;
	r.res_tcpH.th_ack = ntohl(ntohl(tcpH->th_seq) + http_len);
	r.res_tcpH.th_flags = TH_FIN + TH_PUSH + TH_ACK;

	const u_char* res_packet;
	res_packet = (const u_char*)&r;

/*	for (int i = 0; i < 205; i++) {
		if (i % 8 == 0) cout << " ";
		if (i % 16 == 0) cout << endl;
		printf("%02x ", res_packet[i]);
	}*/
	cout << endl;

	return 0;
}

int main() {
	
	ifstream list_file("C:\\CCIT\\http_block\\http_block\\test.txt");
	string ban;
	while (!list_file.eof()) {
		getline(list_file, ban);
		ban_list.insert(ban);
	}
	#define close close
	list_file.close();

	char errbuf[PCAP_ERRBUF_SIZE];
	get_dev();

	pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", d->name, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		struct libnet_ethernet_hdr* ethH = (struct libnet_ethernet_hdr *)packet;

		if (ntohs(ethH->ether_type) == ETHERTYPE_IP) {			// IP check
			packet += sizeof(struct libnet_ethernet_hdr);
			struct libnet_ipv4_hdr* ipH = (struct libnet_ipv4_hdr *)packet;

			if (ipH->ip_p == 0x06) {			// TCP check
				packet += (ipH->ip_hl * 4);
				struct libnet_tcp_hdr* tcpH = (struct libnet_tcp_hdr *)packet;

				if (ntohs(tcpH->th_dport) == 80) {			// HTTP check
					uint32_t http_len = ntohs(ipH->ip_len) - (ipH->ip_hl * 4) - (tcpH->th_off * 4);
					packet += (tcpH->th_off * 4);

					if (http_len != 0) {
						if (check_host(packet)) {
							make_res_packet(ethH, ipH, tcpH, http_len);
							const u_char* a = (u_char*)&r;
							
							if(pcap_sendpacket(handle, a, 205) == 0) cout << "전송 성공" << endl;
							else cout << "실패" << endl;
						}
						
					}
				}
			}
		}
	}
	pcap_close(handle);
	return 0;
}