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
#include <iomanip>
using namespace std;

#pragma pack(push, 1)
struct RadiotapHeader
{
        uint8_t    version;
        uint8_t    pad;
        uint16_t   length;
        uint64_t   presentFlags;
        uint8_t    flags;
        uint8_t    dataRate;
        uint16_t   channelFrequency;
        uint16_t   channelFlags;
        uint8_t    ssiSignal_1;
        uint8_t    wtfTrash;   //strange stuff
        uint16_t   rxFlags;
        uint8_t    ssiSignal_2;
        uint8_t    antenna;
};

struct FrameCtrl
{
    uint8_t   protocolVer    : 2;
    uint8_t   type           : 2;
    uint8_t   subType        : 4;
    uint8_t   toDs           : 1;
    uint8_t   fromDs         : 1;
    uint8_t   moreFlag       : 1;
    uint8_t   retry          : 1;
    uint8_t   powerMgmt      : 1;
    uint8_t   moreData       : 1;
    uint8_t   protectedFrame : 1;
    uint8_t   order          : 1;
};

struct WlanHeader
{
    struct FrameCtrl  frameCtrl;  //2 bytes
           uint16_t   duration;   //2 bytes
           uint8_t    addr1[6];   //6 bytes
           uint8_t    addr2[6];   //6 bytes
           uint8_t    addr3[6];   //6 bytes
           uint16_t   seq_ctrl;   //2 bytes
};

struct BeaconFrameBody
{
    uint64_t  timestamp;
    uint16_t  beaconInterval;
    uint16_t  capacityInformation;
    uint8_t   elementID;
    uint8_t   tagLength;
};

struct List
{
    uint8_t ssid[32];
};
#pragma pack(pop)

void fakeAp(const uint8_t *);
