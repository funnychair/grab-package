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
bool alertInSession(const struct alert &al, const struct session &se);

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
    //for all alert.
    for(unsigned int alertIndex=0; alertIndex<alerts.size(); alertIndex++)
    {
       // alerts[alertIndex].printA();
        for(unsigned int sessionIndex=0; sessionIndex<_sessions.size(); sessionIndex++)
        {
            if(alertInSession(alerts[alertIndex],_sessions[sessionIndex]))
            {
                alerts[alertIndex].printA();
                _sessions[sessionIndex].printSession();
                _sessions[sessionIndex].label = alerts[alertIndex].label;
                alerts.erase(alerts.begin()+alertIndex);
                //cout << alerts[alertIndex].label << endl;
                break;
            }
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
bool alertInSession(const struct alert &al, const struct session &se)
{
    //cout << al.arrival.tv_sec << " & " << se.start.tv_sec << endl;
    if(al.arrival.tv_sec < se.start.tv_sec || al.arrival.tv_sec > se.end.tv_sec)
    {
        return false;
    }
    if(al.arrival.tv_sec == se.start.tv_sec && al.arrival.tv_usec >= se.start.tv_usec)
    {
        //cout << "XX" << endl;
        if(al.ip_scr.s_addr==se.ip_src.s_addr && al.port_src==se.port_src &&
                al.ip_dst.s_addr==se.ip_dst.s_addr && al.port_dst==se.port_dst)
        {
            //cout << "XX" << endl;
            return true;
        }
        else if(al.ip_scr.s_addr==se.ip_dst.s_addr && al.port_src==se.port_dst &&
                al.ip_dst.s_addr==se.ip_src.s_addr && al.port_dst==se.port_src)
        {
            //cout << "XX" << endl;
            return true;
        }
        else return false;
    }
    else if (al.arrival.tv_usec <= se.end.tv_usec)
    {
        if(al.ip_scr.s_addr==se.ip_src.s_addr && al.port_src==se.port_src &&
                al.ip_dst.s_addr==se.ip_dst.s_addr && al.port_dst==se.port_dst) return true;
        else if(al.ip_scr.s_addr==se.ip_dst.s_addr && al.port_src==se.port_dst &&
                al.ip_dst.s_addr==se.ip_src.s_addr && al.port_dst==se.port_src) return true;
        else return false;
    }
    else
    {
        if(al.ip_scr.s_addr==se.ip_src.s_addr && al.port_src==se.port_src &&
                al.ip_dst.s_addr==se.ip_dst.s_addr && al.port_dst==se.port_dst) return true;
        else if(al.ip_scr.s_addr==se.ip_dst.s_addr && al.port_src==se.port_dst &&
                al.ip_dst.s_addr==se.ip_src.s_addr && al.port_dst==se.port_src) return true;
        else return false;
    };
}
