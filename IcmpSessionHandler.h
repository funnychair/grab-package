#ifndef ICMPSESSIONHANDLER
#define ICMPSESSIONHANDLER
#include <iostream>
#include <iomanip>
#include "AbstractHandler.h"

using namespace std;

class IcmpSessionHandler : protected AbstractHandler
{
public:
    IcmpSessionHandler(int, vector<session>&, const struct pcap_pkthdr*, const unsigned char*);
    ~IcmpSessionHandler();
protected:
    using AbstractHandler::addSession;
    void addSession(const struct pcap_pkthdr *header,const unsigned char *packet);
    using AbstractHandler::reflashSession;
    void reflashSession(const struct pcap_pkthdr *header,const unsigned char *packet, session &sess);
    using AbstractHandler::belongToSession;
    bool belongToSession(const struct pcap_pkthdr *header, const struct sniff_ip *ip, session &sess);
};

#endif
