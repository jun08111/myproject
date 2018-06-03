#include <tins/tins.h>
#include <iostream>
#include <cassert>
#include <vector>

using namespace Tins;
using namespace std;

bool tinsDecrypt(PDU& packet)
{
    const Dot11Data& dot11  = packet.rfind_pdu<Dot11Data>();
    const ARP& arp  = packet.rfind_pdu<ARP>();

    if (dot11.from_ds() && !dot11.to_ds())
    {
        cout << "addr1 BSSID: " << dot11.addr1() <<endl
             << "addr2 Src:   " << dot11.addr2() <<endl
             << "addr3 Dst:   " << dot11.addr3() <<endl
             << "Sender Mac:   " << arp.sender_hw_addr() <<endl
             << "Target Mac:   " << arp.target_hw_addr() <<endl

             << endl;
    }

    else if (!dot11.from_ds() && dot11.to_ds())
    {
        cout << "addr1 Dst:   " << dot11.addr1() <<endl
             << "addr2 BSSID: " << dot11.addr2() <<endl
             << "addr3 Src:   " << dot11.addr3() <<endl
             << "Sender Mac:   " << arp.sender_hw_addr() <<endl
             << "Target Mac:   " << arp.target_hw_addr() <<endl
             << endl;
    }

    return true;
}

int main()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_immediate_mode(true);
    Sniffer sniffer("wlan1", config);

    auto decrypt_proxy = Crypto::make_wpa2_decrypter_proxy(&tinsDecrypt);
    decrypt_proxy.decrypter().add_ap_data("information", "833");
    sniffer.sniff_loop(decrypt_proxy);

    return 0;
}
