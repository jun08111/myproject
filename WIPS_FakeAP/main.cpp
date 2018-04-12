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

struct FrameCtrl{
    u_int8_t   protocol_ver : 2;
    u_int8_t   type         : 2;
    u_int8_t   sub_type     : 4;
    u_int8_t   to_ds        : 1;
    u_int8_t   from_ds      : 1;
    u_int8_t   more_flag    : 1;
    u_int8_t   retry        : 1;
    u_int8_t   power_mgmt   : 1;
    u_int8_t   more_data    : 1;
    u_int8_t   wep          : 1;
    u_int8_t   rsvd         : 1;
};

struct IEEE_header{
    struct FrameCtrl  frame_ctrl; //2 bytes
           u_int16_t  duration;   //2 bytes
           u_int8_t   addr1[5];   //6 bytes
           u_int8_t   addr2[5];   //6 bytes
           u_int8_t   addr3[5];   //6 bytes
           u_int16_t  seq_ctrl;   //2 bytes
           u_int8_t   addr4[5];   //6 bytes
};

void IEEE_header(const u_int8_t *);
void Addr1234(const u_int8_t *);

void IEEE_header(const u_int8_t *packet){
    struct IEEE_header *IEh;
    IEh = (struct IEEE_header *)(packet+24);

//* Room-833 (Change  i to Radiotap Header Length)
    printf("*IEEE 802.11 Header\n");
  //printf(" Frame Control: 0x%04x\n", ntohs(IEh->frame_ctrl));
    printf(" To   DS:  %d\n", IEh->frame_ctrl.to_ds);
    printf(" From DS:  %d\n", IEh->frame_ctrl.from_ds);
    printf(" Duration: %d", IEh->duration);
    Addr1234(packet);
    printf("\n");

/*  My House
    IEh = (struct IEEE_header *)(packet+40);
    printf("\n da:    %02x ", packet[i+44]);

*/
    printf("---------------------------------------------------------------------------");
    printf("\n");
}

void Addr1234(const u_int8_t *packet){
    struct IEEE_header *IEh;
    IEh = (struct IEEE_header *)(packet+24);
    u_int8_t td = IEh->frame_ctrl.to_ds;
    u_int8_t fd = IEh->frame_ctrl.from_ds;
    switch(td)
    {
        case 0: switch(fd)
        {
                    case 0:  for(int i=0; i<18; i++){
                                if     (i==0)  printf("\n Receiver    STA: %02x ", packet[i+28]);
                                else if(i==6)  printf("\n Transmitter STA: %02x ", packet[i+28]);
                                else if(i==12) printf("\n BSSID          : %02x ", packet[i+28]);
                                else           printf("%02x ", packet[i+28]);
                                }
                             break;

                    case 1:  for(int i=0; i<18; i++){
                                if     (i==0)  printf("\n Receiver        STA2: %02x ", packet[i+28]);
                                else if(i==6)  printf("\n Transmitter      AP2: %02x ", packet[i+28]);
                                else if(i==12) printf("\n 1st Transmitter STA1: %02x ", packet[i+28]);
                                else           printf("%02x ", packet[i+28]);
                                }
                             break;
                    default: printf("ERROR\n");
                             break;
         }
        break;

        case 1: switch(fd)
        {
                    case 0:  for(int i=0; i<18; i++){
                                if     (i==0)  printf("\n Receiver       AP1: %02x ", packet[i+28]);
                                else if(i==6)  printf("\n Transmitter   STA1: %02x ", packet[i+28]);
                                else if(i==12) printf("\n Last Receiver STA2: %02x ", packet[i+28]);
                                else           printf("%02x ", packet[i+28]);
                                }
                             break;

                    case 1:  for(int i=0; i<26; i++){
                                if     (i==0)  printf("\n Receiver       AP2: %02x ", packet[i+28]);
                                else if(i==6)  printf("\n Transmitter    AP1: %02x ", packet[i+28]);
                                else if(i==12) printf("\n Receiver      STA2: %02x ", packet[i+28]);
                                else if(i==18) printf("\n To DS: 1,");
                                else if(i==19) printf(" From DS: 1");
                                else if(i==20) printf("\n Receiver      STA1: %02x ", packet[i+28]);
                                else           printf("%02x ", packet[i+28]);
                                }
                             break;
                    default: printf("ERROR\n");
                             break;
        }
        break;
    }
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
