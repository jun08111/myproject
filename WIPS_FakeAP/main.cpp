#include "main.h"

void fakeAp(const uint8_t *packet)
{
    struct ManagementFrame *mgmtFrame;
    struct RadiotapHeader *radiotapH;
    struct WifiName *wifiName;
    struct TagBody *tagBody;

    radiotapH = (struct RadiotapHeader *)packet;
    mgmtFrame = (struct ManagementFrame *)(packet + radiotapH->length);
    tagBody   = (struct TagBody *)(packet + radiotapH->length + sizeof(struct ManagementFrame) + sizeof(struct BeaconFrameBody));
    wifiName  = (struct WifiName *)(packet + radiotapH->length + sizeof(struct ManagementFrame) + sizeof(struct BeaconFrameBody) + sizeof(struct TagBody));

    uint8_t type = mgmtFrame->frameCtrl.type;
    uint8_t subtype = mgmtFrame->frameCtrl.subType;

    if(type==0 && subtype==8)  //BeconFrame
    {
        //BSSID***********************************************************************************//
        printf("BSSID: ");
        for(int i=0; i<6; i++)
        {
            printf("%02x ", mgmtFrame->addr3[i]);
        }
        printf("\n");

        //SSID length*****************************************************************************//
        printf("SSID length: %d\n", tagBody->tagLength);

        //SSID************************************************************************************//
        printf("SSID:  ");
        for(int i=0; i<32; i++)
        {
            if(wifiName->ssid[i] == 1)
                break;
            else
                printf("%c", wifiName->ssid[i]);
        }
        printf("\n");

        //Sequence Control*************************************************************************//
        printf("Sequence Control: %04x", ntohs(mgmtFrame->seq_ctrl));
        printf("\n\n");
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
