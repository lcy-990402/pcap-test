#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void ethprint(uint8_t *arr){
    for(int i = 0; i < 6; i += 1){
        printf("%02X", arr[i]);
        if(i < 5) printf("-");
        }
    printf("\n");
}

void ipprint(in_addr arr){
    uint32_t c = htonl(arr.s_addr);
    uint8_t d[4] = {0};
    for(int i = 0; i < 4; i++){
        d[i] = ((uint8_t*)&c)[3-i];
    }
    for(int i = 0; i < 4; i++){
        printf("%d", d[i]);
        if(i < 3) printf(".");
    }
    printf("\n");
}

void tcpprint(uint16_t n){
    printf("%d", n);
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    struct libnet_ethernet_hdr *eth_header;
    struct libnet_ipv4_hdr *ipv4_header;
    struct libnet_tcp_hdr *tcp_header;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("================================\n");
        printf("%u bytes captured\n", header->caplen);

        eth_header = (libnet_ethernet_hdr*)packet;
        printf("1.Ethernet Header\n");
        printf("SOURCE MAC: ");
        ethprint(eth_header->ether_shost);
        printf("Destination MAC: ");
        ethprint(eth_header->ether_dhost);

        packet += sizeof(eth_header);

        ipv4_header = (libnet_ipv4_hdr *)packet;
        printf("2.IPv4 Header\n");
        printf("SOURCE IP: ");
        ipprint(ipv4_header->ip_src);
        printf("Destination IP: ");
        ipprint(ipv4_header->ip_dst);

        packet += sizeof(ipv4_header);

        tcp_header = (libnet_tcp_hdr*)packet;
        printf("3. TCP Header\n");
        printf("SOURCE PORT: ");
        tcpprint(tcp_header->th_sport);
        printf("DESTINATION PORT: ");
        tcpprint(tcp_header->th_dport);

        packet += sizeof(tcp_header);
        unsigned int payload = (header->caplen) - sizeof(eth_header) - sizeof(ipv4_header) - sizeof(tcp_header);
        unsigned int cnt = payload >= 16 ? 16:payload;
        printf("4. Payload\n");
        while(cnt --){
            printf("%02X ", *(packet++));
        }
        printf("\n");
    }

    pcap_close(handle);
}
