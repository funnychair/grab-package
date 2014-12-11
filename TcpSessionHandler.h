#ifndef TCPSESSIONHANDLER
#define TCPSESSIONHANDLER
#include <iostream>
#include <iomanip>
#include "AbstractHandler.h"

using namespace std;

class TcpSessionHandler : protected AbstractHandler
{
public:
    TcpSessionHandler(int, vector<session>&, const struct pcap_pkthdr*, const unsigned char*);
    ~TcpSessionHandler();
protected:
    using AbstractHandler::addSession;
    void addSession(const struct pcap_pkthdr *header,const unsigned char *packet);
    using AbstractHandler::reflashSession;
    void reflashSession(const struct pcap_pkthdr *header,const unsigned char *packet, session &sess);
    using AbstractHandler::belongToSession;
    bool belongToSession(const struct pcap_pkthdr *header, const unsigned char *packet, session &sess);
};

#endif
