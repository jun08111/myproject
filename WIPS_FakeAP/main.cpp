#include "main.h"

void fakeAp(const uint8_t *packet)
{
    struct WlanHeader *wlanH;
    struct RadiotapHeader *radiotapH;

    radiotapH = (struct RadiotapHeader *)packet;
    wlanH = (struct WlanHeader *)(packet + radiotapH->length);

    uint8_t type = wlanH->frameCtrl.type;
    uint8_t subtype = wlanH->frameCtrl.subType;


    if(type==0 && subtype==8)  //BeconFrame
    {
        struct List *list;
        //BSSID***********************************************************************************//
        printf("BSSID: ");
        for(int i=0; i<6; i++)
        {
            printf("%02x ", wlanH->addr3[i]);
        }
        printf("\n");

        //SSID************************************************************************************//
        packet += (radiotapH->length + sizeof(struct WlanHeader) + sizeof(struct BeaconFrameBody));
        list = (struct List *)packet;
        printf("SSID:  ");
        for(int i=0; i<32; i++)
        {
            if(packet[i] == 1)
                break;

            printf("%c ", list->ssid[i]);
        }
        printf("\n\n");

        //Check White or Black*******************************************************************//
        if(wlanH->addr3[]^WhiteListApMac[] == 0)
        {
            if(list->ssid[i]^WhiteListSSID[] == 0)
            {
                BlackList
            }
        }
        if(list->ssid[i]^WhiteListSSID[] == 0)
        {
            if(wlanH->addr3[]^WhiteListApMac[] == 0)
            {
                BlackList
            }
        }
        //****************************************************************************************//

    }
}

int main(int argc, char* argv[])
{
    char *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const uint8_t *packet;

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

        fakeAp(packet);

    }
    pcap_close(handle);
    return 0;
}
