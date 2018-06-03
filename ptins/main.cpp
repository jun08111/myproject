#include <tins/tins.h>
#include <iostream>
#include <cassert>

using namespace Tins;
using namespace std;

bool tinsPcap(PDU& packet)
{
    const EthernetII& eth = packet.rfind_pdu<EthernetII>();
    cout << "Dst Mac Address: " << eth.dst_addr() << endl
         << "Src Mac Address: " << eth.src_addr() << endl;

    const IP& ip = packet.rfind_pdu<IP>();
    cout << "Src IP Addr: " << ip.src_addr() << endl
         << "Dst IP Addr: " << ip.dst_addr() << endl;

    const TCP& tcp = packet.rfind_pdu<TCP>();
    cout << "Src Port: " << tcp.sport() << endl
         << "Dst Port: " << tcp.dport() << endl << endl;

    const RawPDU& rawPDU = packet.rfind_pdu<RawPDU>();
    cout << "Pay load: " << endl;
    for(int i=0; i<rawPDU.size(); i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)rawPDU.payload().data()[i]<<" ";
    }

    return true;
}

int main()
{
    SnifferConfiguration config;
    config.set_filter("port 80");
    config.set_promisc_mode(true);
    config.set_immediate_mode(true);
    Sniffer sniffer("wlan0", config);
    sniffer.sniff_loop(tinsPcap);

    return 0;
}

