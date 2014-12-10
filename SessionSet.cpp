#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "SessionSet.h"
#include "jaychang.h"

#define SIZE_ETHERNET 14


using namespace std;

SessionSet::SessionSet(int timeout)
{
    _timeout = timeout;
}
SessionSet::~SessionSet(){}

void SessionSet::addPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    _ethernet = (const struct sniff_ethernet*)(packet);
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl&0x0f)*4);
    u_short sport = _tcp->th_sport;
    u_short dport = _tcp->th_dport;
    if(_ip->ip_p==0x01)sport = dport = 0;
    bool newflag = true;
    //search session of the packet.
    vector<session>::iterator se_it;
    for(se_it = _sessions.begin(); se_it != _sessions.end(); se_it++)
    {
        //check in time windows.
        if((header->ts.tv_sec)<(se_it->end.tv_sec+_timeout))
        {
            //check in session or not.
            if
            (
                (
                    (_ip->ip_src.s_addr==se_it->ip_src.s_addr)
                    &&
                    (sport==se_it->port_src)
                    &&
                    (_ip->ip_dst.s_addr==se_it->ip_dst.s_addr)
                    &&
                    (dport==se_it->port_dst)
                )
                ||
                (
                    (_ip->ip_src.s_addr==se_it->ip_dst.s_addr)
                    &&
                    (sport==se_it->port_dst)
                    &&
                    (_ip->ip_dst.s_addr==se_it->ip_src.s_addr)
                    &&
                    (dport==se_it->port_src)
                )
            )
            {
                reflashSession(header, packet ,se_it);
                newflag = false;
                break;
            }
        }
        else
        {
            //TODO output session or do nothing.
        }
    }
    if(newflag==true)
    {
        addSession(header, packet);
        //cout << _sessions.size() << endl;
    }

}
void SessionSet::reflashSession(const struct pcap_pkthdr *header, const u_char *packet, vector<session>::iterator se_it )
{
    //cout << "reflashSession.==" << endl;
    se_it->end.tv_sec = header->ts.tv_sec;
    se_it->end.tv_usec = header->ts.tv_usec;
    se_it->p_number++;
}
void SessionSet::addSession(const struct pcap_pkthdr *header, const u_char *packet)
{
    _ethernet = (const struct sniff_ethernet*)(packet);
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    //assume packet is tcp to get the sport and dport for build the inint value.
    struct session newSession = {header->ts, _ip->ip_src, _ip->ip_dst};
    if(_ip->ip_p==0x06)
    {
        _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
        newSession.port_src = _tcp->th_sport;
        newSession.port_dst = _tcp->th_dport;
        newSession.protocol = "tcp";
        //TODO:add the function to detect features for tcp protocol.
    }
    else if(_ip->ip_p==0x11)
    {
        _udp = (const struct sniff_udp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
        newSession.port_src = _udp->th_sport;
        newSession.port_dst = _udp->th_dport;
        newSession.protocol = "udp";
        //TODO:add the function to detect features for udp protocol.
    }
    else if(_ip->ip_p==0x01)
    {
        _icmp = (const struct sniff_icmp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
        newSession.port_src = 0;
        newSession.port_dst = 0;
        newSession.protocol = "icmp";
        //TODO:add the function to detect features for icmp protocol.
    }
    //TODO add the function for all protocol.
    TrafficFeature tf(header,packet,_sessions);
    cout << tf.countOfSameService() << ' ' << tf.percentageOfSameServiceInSameHost() << endl;
    _sessions.push_back(newSession);
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
