#include <iostream>
#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>

using namespace std;

struct ether_header *eh;
struct iphdr *iph;
struct tcphdr *tcph;

int main()
{
    char *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    struct pcap_pkthdr *header;
    const u_char *packet;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    u_char *payload;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    while(int result = pcap_next_ex(handle, &header, &packet) >=0){
        if      (result == 0)  continue;      //Timeout expired, There is no packet.
        else if (result == -1) break;         //-1: error,Signal Lost
        else if (result == -2){               //-2: EOF, No more packet from the packet savefile.
                               fprintf(stderr, "No more packet from the packet savefile.");
                               break;
        }
        eh = (struct ether_header *)packet;
        printf("*Ethernet Header\n");

        printf("Dst Mac Address: ");
        for(int i=0; i<6; i++){
            printf("%02x ", eh->ether_dhost[i]);
        }
        printf("\nSrc Mac Address: ");
        for(int i=0; i<6; i++){
            printf("%02x ", eh->ether_shost[i]);
        }
        printf("\n");

        packet += sizeof(struct ether_header);
        char buf[INET_ADDRSTRLEN];
        if (ntohs(eh->ether_type) == ETHERTYPE_IP){
            iph = (struct iphdr *)packet;
            printf("*IP Header\n");
            printf("Src IP Addr: %s\n", inet_ntop(AF_INET,&iph->saddr, buf, sizeof(buf))); //inet_ntop: binary -> human-readable text
            printf("Dst IP Addr: %s\n", inet_ntop(AF_INET,&iph->daddr, buf, sizeof(buf)));
        }

        packet += iph->ihl * 4;
        if(iph->protocol == IPPROTO_TCP){
            tcph = (struct tcphdr *) packet;
            printf("*TCP Header\n");
            printf("Src Port: %d\n", ntohs(tcph->th_sport));
            printf("Dst Port: %d\n", ntohs(tcph->th_dport));
            printf("seq: %d\n", ntohs(tcph->seq));

            int paylen;
            paylen = int(ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->th_off * 4));
            printf("paylen: %d\n", paylen);

            payload =(u_char *)(packet + (tcph->th_off * 4));
            printf("payload hexa Value\n");
            int cl = 0;
            while(paylen--){
                printf("%02x ", *(payload++));
                if((++cl % 16) == 0) printf("\n");
            }
            printf("\n\n");
        }

    }
    pcap_close(handle);
    return 0;
}
