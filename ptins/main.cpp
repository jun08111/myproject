#include <tins/tins.h>
#include <cassert>
#include <iostream>
#include <vector>
using namespace Tins;
using namespace std;
/*
int main()
{
    vector<Packet> vt;
    SnifferConfiguration config;
    config.set_filter("port 80");
    config.set_promisc_mode(true);
    config.set_snap_len(400);
    Sniffer sniffer("wlan1", config);
    unique_ptr<PDU> pdu_ptr(sniffer.next_packet());

    while (vt.size() != 100)
    {
        vt.push_back(sniffer.next_packet()); //next_packet returns a PtrPacket, which can be implicitly converted to Packet.
    }

    for (const auto& packet : vt)
    {
        cout << "Dst Mac:  "  << packet.pdu()->rfind_pdu<EthernetII>().dst_addr() <<endl
             << "Src Mac:  "  << packet.pdu()->rfind_pdu<EthernetII>().src_addr() <<endl
             << "Src addr: " << packet.pdu()->rfind_pdu<IP>().src_addr() << endl
             << "Dst addr: " << packet.pdu()->rfind_pdu<IP>().dst_addr() << endl
             << "Src port: " << packet.pdu()->rfind_pdu<TCP>().sport() <<endl
             << "Dst port: " << packet.pdu()->rfind_pdu<TCP>().dport() <<endl
             << endl;

    }

}
*/
bool handler(const Packet&)
{
    vector<Packet> vt;
    SnifferConfiguration config;
    config.set_filter("port 80");
    config.set_promisc_mode(true);
    Sniffer sniffer("wlan0",config);

    vt.push_back(sniffer.next_packet()); //next_packet returns a PtrPacket, which can be implicitly converted to Packet.

    for (const auto& packet : vt)
    {
        cout << "Dst Mac:  " << packet.pdu()->rfind_pdu<EthernetII>().dst_addr() <<endl
             << "Src Mac:  " << packet.pdu()->rfind_pdu<EthernetII>().src_addr() <<endl
             << "Src addr: " << packet.pdu()->rfind_pdu<IP>().src_addr() << endl
             << "Dst addr: " << packet.pdu()->rfind_pdu<IP>().dst_addr() << endl
             << "Src port: " << packet.pdu()->rfind_pdu<TCP>().sport() <<endl
             << "Dst port: " << packet.pdu()->rfind_pdu<TCP>().dport() <<endl
             << endl;
    }
    return true;
}

int main()
{
    Sniffer sniffer("wlan0");
    //auto decrypt_proxy = Crypto::make_wpa2_decrypter_proxy(&handler);
    //decrypt_proxy.decrypter().add_ap_data("jeon0926","Jeon");
    sniffer.sniff_loop(&handler);
    //sniffer.sniff_loop(decrypt_proxy);
    return 0;
}
