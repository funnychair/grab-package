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
    void labelSession(vector<alert>& alerts);
    void outputSession(string path);
    
private:
    unsigned int _timeout;
    vector<session> _sessions;
    const class sniff_ethernet *_ethernet;
    const class  sniff_ip *_ip;
    const class sniff_tcp *_tcp;
    const char *_payload;
    void reflashSession(const struct pcap_pkthdr *header, const u_char *packet,
            vector<session>::iterator se_it);
    void addSession(const struct pcap_pkthdr *header, const u_char *packet);
};
