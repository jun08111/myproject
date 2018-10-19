#include "main.h"
#include "kmeans.h"

void fakeAp(const uint8_t *packet, uint16_t *cntApRss, char *rss)
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
        printf("--------------------------------------------------------------\n");
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
        printf("\n");

        //rss, conunt rss(cnt), avg of rss(AP1)****************************************************//
        if((type==0 && subtype==8) || (type==0 && subtype==4) || (type==0 && subtype==5))
        {
            rss[*cntApRss]=radiotapH->ssiSignal_1;
            printf("rss: %d, count: %d\n\n", radiotapH->ssiSignal_1, *cntApRss);
            (*cntApRss)++;

            if(*cntApRss % 10 == 1 && *cntApRss != 1) //10 cycle
            {
                kmeanAlgo(*cntApRss, rss);
            }
        }
    }

}

void kmeanAlgo(uint16_t cntApRss, char *rss)
{
    srand (time(NULL));

    int total_points = cntApRss;//countpacket
    int K = 1;
    int total_values = 1;
    int has_name = 0;
    int max_iterations = 100;//Stop when you check 1000 rss

    vector<Point> points;
    string point_name;


    for(int i = 0; i < total_points; i++)
    {
        vector<double> values;

        double value = rss[i];//SsiSignal[i];
        values.push_back(value);

        if(has_name)
        {
            Point p(i, values, point_name);
            points.push_back(p);
        }
        else
        {
            Point p(i, values);
            points.push_back(p);
        }
    }
    KMeans kmeans(K, total_points, total_values, max_iterations); //(ap count, packet count, 1(RSS), how many times u want to check)
    kmeans.run(points);
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

    uint16_t cntApRss = 1;
    char rss[1000];
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

        fakeAp(packet, &cntApRss, rss);

    }
    pcap_close(handle);
    return 0;
}
