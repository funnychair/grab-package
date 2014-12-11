#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "StructSet.h"

class TrafficFeature
{
public:
    TrafficFeature(vector<session> &sessionV);
private:
    int _count_host = 0;
    int _count_srv = 0;
    int _count_host_srv = 0;
    int _count_host_SYN = 0;
    int _count_host_REJ = 0;
    int _count_srv_SYN = 0;
    int _count_srv_REJ = 0;
    int _count_host_same_src_port = 0;
    int _count_host_same_srv_diff_src_host = 0;
};
