#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "StructSet.h"

class BasicFeature
{
public:
    string service(const unsigned char * packet);
    int isurgent(const unsigned char * packet);

private:
};
