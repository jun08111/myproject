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

struct IEEE_header{
    u_int16_t   fc;         //2 bytes
    u_int16_t   duration;   //2 bytes
    u_int8_t    da[5];      //6 bytes
    u_int8_t    sa[5];      //6 bytes
    u_int8_t    bssid[5];   //6 bytes
    u_int16_t   seq_ctrl;   //2 bytes
};

void IEEE_header(const u_int8_t *);

void IEEE_header(const u_int8_t *packet){
    struct IEEE_header *IEh;
    IEh = (struct IEEE_header *)(packet+40);

    printf(" *IEEE 802.11 Header\n");
    printf(" Frame Control: 0x%04x\n",ntohs(IEh->fc));
    printf(" Duration: %d", IEh->duration);
    for(int i=0; i<18; i++){
        if     (i==0)  printf("\n da:    %02x ", packet[i+44]);
        else if(i==6)  printf("\n sa:    %02x ", packet[i+44]);
        else if(i==12) printf("\n BSSID: %02x ", packet[i+44]);
        else           printf("%02x ", packet[i+44]);
    }
    printf("\n Seq_Ctrl: %d\n", IEh->seq_ctrl);
    printf(" Seq_Ctrl: %02x%02x\n", packet[62],packet[63]);

    /*
    printf("Frame Control: %02x%02x\n",packet[40],packet[41]);
    printf("Duration: %02x%02x\n", packet[42],packet[43]);
    printf("da:    %02x %02x %02x %02x %02x %02x\n", packet[44],packet[45],packet[46],packet[47],packet[48],packet[49]);
    printf("sa:    %02x %02x %02x %02x %02x %02x\n", packet[50],packet[51],packet[52],packet[53],packet[54],packet[55]);
    printf("BSSID: %02x %02x %02x %02x %02x %02x\n", packet[56],packet[57],packet[58],packet[59],packet[60],packet[61]);
    printf("SequncControl: %02x%02x\n", packet[62],packet[63]);
    */
    printf("---------------------------------------------------------------------------");
    printf("\n");
}

int main(int argc, char* argv[])
{
    char *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;

    if (argc != 2) {
            cout << "Usage: " <<* argv << " <Device>" << endl;
            return 1;
        }

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

    while(int result = pcap_next_ex(handle, &header, &packet) >=0){
        if      (result == 0)  continue;      //Timeout expired, There is no packet.
        else if (result == -1) break;         //-1: error,Signal Lost
        else if (result == -2)                //-2: EOF, No more packet from the packet savefile.
        {
            fprintf(stderr, "No more packet from the packet savefile.");
            break;
        }

        IEEE_header(packet);
    }
    pcap_close(handle);
    return 0;
}
