#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <time.h>
#include <sys/socket.h>
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
    time.tm_year = 113;
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
        tmp.arrival.tv_sec = mktime(&time);
        
        //
        ss << alertContent.substr(15,7);
        ss >> tmp.arrival.tv_usec;
        ss.clear();
        //cout << time.tm_mon << " " << time.tm_mday << " " << time.tm_hour << " " << time.tm_min << " " << time.tm_sec << endl;

        int startClassification = alertContent.find( "[Classification:" ) + 16;
        //cout << startClassification << endl;
        int endClassification = alertContent.find_first_of( "]", startClassification);
        //set alert label.
        tmp.label = alertContent.substr( startClassification, (endClassification-startClassification));
        //cout << tmp.label << endl;
        
        //set alert IP and PORT.
        
        int sIpStart = alertContent.find_first_of( "}", endClassification)+1;
        if(alertContent.substr(sIpStart-6,6)!="{ICMP}")
        {
            int sPortStart = alertContent.find_first_of( ":", sIpStart);
            int sPortEnd = alertContent.find_first_of( " ", sPortStart);
            int dIpStart = alertContent.find_first_of( " ", sPortEnd+1);
            int dPortStart = alertContent.find_first_of( ":", dIpStart);

            string a = alertContent.substr(sIpStart+1,(sPortStart-sIpStart-1));
            int k = inet_aton(a.c_str(), &(tmp.ip_scr));

            ss << alertContent.substr(sPortStart+1,(sPortEnd-sPortStart-1));
            ss >> tmp.port_src;
            ss.clear();

            a = alertContent.substr(dIpStart+1,(dPortStart-dIpStart-1));
            k = inet_aton(a.c_str(), &(tmp.ip_dst));

            ss << alertContent.substr(dPortStart+1);
            ss >> tmp.port_dst;
            ss.clear();
        }
        else
        {
            tmp.port_dst = tmp.port_src = 0;
            int sIpEnd = alertContent.find_first_of( " ", sIpStart);
            int dIpStart = alertContent.find_first_of( ">", sIpEnd+1);
            cout << "!" << alertContent.substr(dIpStart+2) << "!" << endl;
            string a = alertContent.substr(sIpStart+1,(sIpEnd-sIpStart-1));
            int k = inet_aton(a.c_str(), &(tmp.ip_scr));
            a = alertContent.substr(dIpStart+2);
            k = inet_aton(a.c_str(), &(tmp.ip_dst));
            //ss << 
        }
        _alert.push_back(tmp);
        getline(file, alertContent);
    }
}
vector<alert> AlertSet::getAlert()
{
    return _alert;
}
