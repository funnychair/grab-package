#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "StructSet.h"

using namespace std;

class SessionSet
{
public:
    SessionSet(int timeout);
    ~SessionSet();
    void addPacket(unsigned char *args, const struct pcap_pkthdr *header, 
            const unsigned char *packet);
    void setTrafficFeatures();
    void labelSession(vector<alert>& alerts);
    void outputSession(string path);
    
private:
    unsigned int _timeout;
    vector<session> _sessions;
    const struct sniff_ethernet *_ethernet;
    const struct sniff_ip *_ip;
    const struct sniff_tcp *_tcp;
    const struct sniff_udp *_udp;
    const struct sniff_icmp *_icmp;
    const char *_payload;
};
