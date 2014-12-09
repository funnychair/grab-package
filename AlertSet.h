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

class AlertSet
{
public:
    AlertSet(string path);
    ~AlertSet();
    vector<alert> getAlert();

private:
    vector<alert> _alert;
    void snortResolve(ifstream &file);
};
