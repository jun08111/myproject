#include "main.h"

void WlanHeader(const u_int8_t *packet){
    struct WlanHeader *wlanH;
    wlanH = (struct WlanHeader *)(packet+24);
    printf("*Wlan Header 802.11 Header\n");
    printf(" To   DS:  %d\n", wlanH->frameCtrl.toDs);
    printf(" From DS:  %d\n", wlanH->frameCtrl.fromDs);
    printf(" Duration: %d", wlanH->duration);
    Addr1234(packet);
    printf("\n");
    printf("---------------------------------------------------------------------------");
    printf("\n");
}

void Addr1234(const u_int8_t *packet)
{
    struct WlanHeader *wlanH;
    wlanH = (struct WlanHeader *)(packet+24);
    u_int8_t td = wlanH->frameCtrl.toDs;
    u_int8_t fd = wlanH->frameCtrl.fromDs;

    switch(td)
    {
    case 0: switch(fd)
            {
            case 0: for(int i=0; i<18; i++)
                {
                if     (i==0)
                    printf("\n Receiver    STA: %02x ", packet[i+28]);
                else if(i==6)
                    printf("\n Transmitter STA: %02x ", packet[i+28]);
                else if(i==12)
                    printf("\n BSSID          : %02x ", packet[i+28]);
                else
                    printf("%02x ", packet[i+28]);
                }
            break;

            case 1: for(int i=0; i<18; i++)
                {
                if     (i==0)
                    printf("\n Receiver        STA2: %02x ", packet[i+28]);
                else if(i==6)
                    printf("\n Transmitter      AP2: %02x ", packet[i+28]);
                else if(i==12)
                    printf("\n 1st Transmitter STA1: %02x ", packet[i+28]);
                else
                    printf("%02x ", packet[i+28]);
                }
            break;

            default: printf("ERROR\n");
            break;
            }
    break;

    case 1: switch(fd)
            {
            case 0: for(int i=0; i<18; i++)
                {
                if     (i==0)
                    printf("\n Receiver      STA:  %02x ", packet[i+28]);
                else if(i==6)
                    printf("\n Transmitter   STA:  %02x ", packet[i+28]);
                else if(i==12)
                    printf("\n Last Receiver STA2: %02x ", packet[i+28]);
                else
                    printf("%02x ", packet[i+28]);
                }
            break;

            case 1:  for(int i=0; i<18; i++)
                {
                if     (i==0)
                    printf("\n Receiver       AP2: %02x ", packet[i+28]);
                else if(i==6)
                    printf("\n Transmitter    AP1: %02x ", packet[i+28]);
                else if(i==12)
                    printf("\n Receiver      STA2: %02x ", packet[i+28]);
                else if(i==18)
                    printf("\n To DS: 1,");
                else if(i==19)
                    printf(" From DS: 1");
                else if(i==20)
                    printf("\n Receiver      STA1: %02x ", packet[i+28]);
                else
                    printf("%02x ", packet[i+28]);
                }
            break;

            default: printf("ERROR\n");
            break;
            }
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

//https://github.com/appneta/tcpreplay/releases ////download
//pragma push pop
