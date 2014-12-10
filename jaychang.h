#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "StructSet.h"

class TrafficFeature
{
public:
//it detect when add a new session.
    TrafficFeature(const struct pcap_pkthdr *header, const u_char *packet, vector<session> &sessionV);
    int countOfSameHost() {return _count_host;}
    //float percentageOfSYNerrorInSameHost();
    //float percentageOfREJerrorInSameHost();
    float percentageOfSameServiceInSameHost() {return (float)_count_host_srv/(float)_count_host;}
    float percentageOfDifferentServiceInSameHost() {return ((float)(_count_host-_count_host_srv)/(float)_count_host);}
    
    int countOfSameService() {return _count_srv;}
    //float percentageOfSYNerrorInSameService();
    //float percentageOfREJerrorInSameService();
    float percentageOfDifferentHostInSameService() {return ((float)(_count_srv-_count_host_srv)/(float)_count_srv);}
private:
    int _count_host;
    int _count_host_srv;
    int _count_srv;
};
