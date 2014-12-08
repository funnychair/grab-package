#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AlertSet.h"

using namespace std;

AlertSet::AlertSet(string path)
{
    ifstream alertFile;
    alertFile.open(path.c_str(),ios::in);
    if(!alertFile)
    {
        cout << "alert file (" << path << ") open fail.\n";
        return;
    }
    snortResolve(alertFile);
    cout << "--------" << endl;
}
AlertSet::~AlertSet(){}
void AlertSet::snortResolve(ifstream &file)
{
    string alertContent;
    struct tm time;
    time.tm_year = 114;
    getline(file, alertContent);
    while(!file.eof())
    {
        //TODO: resolve snort text.
        stringstream ss;
        alert tmp;
        //set alert timestamp.
        ss << alertContent.substr(0,2);
        ss >> time.tm_mon;
        time.tm_mon--;
        ss.clear();
        ss << alertContent.substr(3,2);
        ss >> time.tm_mday;
        ss.clear();
        ss << alertContent.substr(6,2);
        ss >> time.tm_hour;
        ss.clear();
        ss << alertContent.substr(9,2);
        ss >> time.tm_min;
        ss.clear();
        ss << alertContent.substr(12,2);
        ss >> time.tm_sec;
        ss.clear();
        ss << alertContent.substr(15,7);
        ss >> tmp.arrival.tv_usec;
        ss.clear();
        //cout << time.tm_mon << " " << time.tm_mday << " " << time.tm_hour << " " << time.tm_min << " " << time.tm_sec << endl;
        cout << mktime(&time); 
        tmp.arrival.tv_sec = mktime(&time);
        //set alert IP and PORT.
        //tmp test
        tmp.ip_scr.s_addr = 402761920;
        tmp.ip_dst.s_addr = 2973889852;
        tmp.port_src = 5632;
        tmp.port_dst = 26804;
        //set alert label.
        tmp.label = alertContent;
        _alert.push_back(tmp);
        getline(file, alertContent);
    }
}
vector<alert>* AlertSet::getAlert()
{
    return &_alert;
}
