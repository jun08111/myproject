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

using namespace std;

struct FrameCtrl{
    u_int8_t   protocolVer : 2;
    u_int8_t   type         : 2;
    u_int8_t   subType     : 4;
    u_int8_t   toDs        : 1;
    u_int8_t   fromDs      : 1;
    u_int8_t   moreFlag    : 1;
    u_int8_t   retry        : 1;
    u_int8_t   powerMgmt   : 1;
    u_int8_t   moreData    : 1;
    u_int8_t   wep          : 1;
    u_int8_t   rsvd         : 1;
};

struct WlanHeader{
    struct FrameCtrl  frameCtrl;  //2 bytes
           u_int16_t  duration;   //2 bytes
           u_int8_t   addr1[5];   //6 bytes
           u_int8_t   addr2[5];   //6 bytes
           u_int8_t   addr3[5];   //6 bytes
           u_int16_t  seq_ctrl;   //2 bytes
           u_int8_t   addr4[5];   //6 bytes
};

struct ApMacAddr{
    u_int8_t apMac[5];
};

void WlanHeader(const u_int8_t *);
void Addr1234(const u_int8_t *);
