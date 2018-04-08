#include <tins/tins.h>
#include <cassert>
#include <iostream>
#include <string>

using namespace std;
using namespace Tins;

int main() {
    HWAddress<6> hw_addr("01:de:22:01:09:af");

    std::cout << hw_addr << std::endl;
    std::cout << std::hex;
    // prints individual bytes
    for (auto i : hw_addr) {
        std::cout << static_cast<int>(i) << std::endl;
    }
}

/*
int main()
{
    char *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;

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
    }
}
*/
