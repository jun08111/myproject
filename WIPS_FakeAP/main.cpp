#include "main.h"

void WlanHeader(const u_int8_t *packet)
{
    struct WlanHeader *wlanH;
    packet += sizeof(struct RadiotapHeader);
    wlanH = (struct WlanHeader *)packet;
    //for(int i=0;i<100;i++)printf("%02x ", packet[i]);
    printf("*Wlan Header 802.11 Header\n");
    printf(" To   DS:  %d\n", wlanH->frameCtrl.toDs);
    printf(" From DS:  %d", wlanH->frameCtrl.fromDs);
    Addr1234(packet);
    printf("\n-------------------------------------------------------------------------\n");
}

void Addr1234(const u_int8_t *packet)
{
    struct WlanHeader *wlanH;
    wlanH = (struct WlanHeader *)packet;
    u_int8_t td = wlanH->frameCtrl.toDs;
    u_int8_t fd = wlanH->frameCtrl.fromDs;

    switch(td)
    {
    case 0: switch(fd)
            {
            case 0:
                     printf("\n Receiver    STA: %02x %02x %02x %02x %02x %02x ", wlanH->addr1[0], wlanH->addr1[1], wlanH->addr1[2], wlanH->addr1[3] ,wlanH->addr1[4], wlanH->addr1[5]);
                     printf("\n Transmitter STA: %02x %02x %02x %02x %02x %02x ", wlanH->addr2[0], wlanH->addr2[1], wlanH->addr2[2], wlanH->addr2[3] ,wlanH->addr2[4], wlanH->addr2[5]);
                     printf("\n BSSID          : %02x %02x %02x %02x %02x %02x ", wlanH->addr3[0], wlanH->addr3[1], wlanH->addr3[2], wlanH->addr3[3] ,wlanH->addr3[4], wlanH->addr3[5]);
                     break;

            case 1:
                     printf("\n Receiver        STA2: %02x %02x %02x %02x %02x %02x ", wlanH->addr1[0], wlanH->addr1[1], wlanH->addr1[2], wlanH->addr1[3] ,wlanH->addr1[4], wlanH->addr1[5]);
                     printf("\n Transmitter      AP2: %02x %02x %02x %02x %02x %02x ", wlanH->addr2[0], wlanH->addr2[1], wlanH->addr2[2], wlanH->addr2[3] ,wlanH->addr2[4], wlanH->addr2[5]);
                     printf("\n 1st Transmitter STA1: %02x %02x %02x %02x %02x %02x ", wlanH->addr3[0], wlanH->addr3[1], wlanH->addr3[2], wlanH->addr3[3] ,wlanH->addr3[4], wlanH->addr3[5]);
                     break;

            default: printf("ERROR\n");
                     break;
            }
            break;

    case 1: switch(fd)
            {
            case 0:
                     printf("\n Receiver      STA:  %02x %02x %02x %02x %02x %02x ", wlanH->addr1[0], wlanH->addr1[1], wlanH->addr1[2], wlanH->addr1[3] ,wlanH->addr1[4], wlanH->addr1[5]);
                     printf("\n Transmitter   STA:  %02x %02x %02x %02x %02x %02x ", wlanH->addr2[0], wlanH->addr2[1], wlanH->addr2[2], wlanH->addr2[3] ,wlanH->addr2[4], wlanH->addr2[5]);
                     printf("\n Last Receiver STA2: %02x %02x %02x %02x %02x %02x ", wlanH->addr3[0], wlanH->addr3[1], wlanH->addr3[2], wlanH->addr3[3] ,wlanH->addr3[4], wlanH->addr3[5]);
                     break;

            case 1:
                     printf("\n Receiver       AP2: %02x %02x %02x %02x %02x %02x ", wlanH->addr1[0], wlanH->addr1[1], wlanH->addr1[2], wlanH->addr1[3] ,wlanH->addr1[4], wlanH->addr1[5]);
                     printf("\n Transmitter    AP1: %02x %02x %02x %02x %02x %02x ", wlanH->addr2[0], wlanH->addr2[1], wlanH->addr2[2], wlanH->addr2[3] ,wlanH->addr2[4], wlanH->addr2[5]);
                     printf("\n Receiver      STA2: %02x %02x %02x %02x %02x %02x ", wlanH->addr3[0], wlanH->addr3[1], wlanH->addr3[2], wlanH->addr3[3] ,wlanH->addr3[4], wlanH->addr3[5]);
                     printf("\n Receiver      STA1: %02x %02x %02x %02x %02x %02x ", wlanH->addr4[0], wlanH->addr4[1], wlanH->addr4[2], wlanH->addr4[3] ,wlanH->addr4[4], wlanH->addr4[5]);
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
    const u_int8_t *packet;

    if (argc != 2)
    {
        cout << "Usage: " <<* argv << " <Device>" << endl;
        return 1;
    }

    dev = argv[1];

    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    while(int result = pcap_next_ex(handle, &header, &packet) >=0)
    {
        if(result == 0)       //Timeout expired, There is no packet.
            continue;

        else if(result == -1) //-1: error,Signal Lost
            break;

        else if(result == -2) //-2: EOF, No more packet from the packet savefile.
        {
            fprintf(stderr, "No more packet from the packet savefile.");
            break;
        }

        WlanHeader(packet);
    }
    pcap_close(handle);
    return 0;
}
