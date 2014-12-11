#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "SessionSet.h"
#include "IcmpSessionHandler.h"
#include "UdpSessionHandler.h"
#include "TcpSessionHandler.h"
#include "jaychang.h"

#define SIZE_ETHERNET 14


using namespace std;

bool tcpBelongToSession(const unsigned char *packet, vector<session> &sess);
bool udpBelongToSession(const unsigned char *packet, vector<session> &sess);
bool icmpBelongToSession(const unsigned char *packet, vector<session> &sess);

SessionSet::SessionSet(int timeout)
{
    _timeout = timeout;
}
SessionSet::~SessionSet(){}

void SessionSet::addPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    _ethernet = (const struct sniff_ethernet*)(packet);
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    if(_ip->ip_p==0x06)
    {
        TcpSessionHandler handler(_timeout,_sessions,header,packet);
    }
    else if(_ip->ip_p==0x11)
    {
        UdpSessionHandler hander(_timeout,_sessions,header,packet);
    }
    else if(_ip->ip_p==0x01)
    {
        IcmpSessionHandler handler(_timeout,_sessions,header,packet);
    }
}
void SessionSet::setTrafficFeatures()
{
    TrafficFeature tf(_sessions);
}
void SessionSet::labelSession(vector<alert>& alerts)
{
    //for all sessions
    for(unsigned long sessionIndex=0; sessionIndex<_sessions.size(); sessionIndex++)
    {
        //if(alerts.empty())break;
        //for all alert.
        for(unsigned long alertIndex=0; alertIndex<alerts.size(); alertIndex++)
        {
            if(_sessions[sessionIndex].end.tv_sec>alerts[alertIndex].arrival.tv_sec);
            else if(_sessions[sessionIndex].end.tv_sec < alerts[alertIndex].arrival.tv_sec)break;
            else 
            {
                if(_sessions[sessionIndex].end.tv_usec >= alerts[alertIndex].arrival.tv_usec);
                else if(_sessions[sessionIndex].end.tv_usec < alerts[alertIndex].arrival.tv_usec)break;
            }
            _sessions[sessionIndex].label = alerts[alertIndex].label;
            alerts.erase(alerts.begin()+alertIndex);
            //cout << alerts[alertIndex].label << endl;
        }
    }
}
void SessionSet::outputSession(string path)
{
    ofstream file;
    file.open(path.c_str(),ios::out);
    vector<session>::iterator se_it = _sessions.begin();
    for(; se_it!=_sessions.end(); se_it++)
    {
        //se_it->printSession();
        file << se_it->outputSession();
    }
    cout << "session number is " << _sessions.size() << endl;
}
