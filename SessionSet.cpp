#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "SessionSet.h"

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
                    (_tcp->th_sport==se_it->port_src)
                    &&
                    (_ip->ip_dst.s_addr==se_it->ip_dst.s_addr)
                    &&
                    (_tcp->th_dport==se_it->port_dst)
                )
                ||
                (
                    (_ip->ip_src.s_addr==se_it->ip_dst.s_addr)
                    &&
                    (_tcp->th_sport==se_it->port_dst)
                    &&
                    (_ip->ip_dst.s_addr==se_it->ip_src.s_addr)
                    &&
                    (_tcp->th_dport==se_it->port_src)
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
    //if()
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl&0x0f)*4);
    //cout << "addSession.\n" << endl;
    struct session newSession;
    newSession.start.tv_sec = header->ts.tv_sec;
    newSession.start.tv_usec = header->ts.tv_usec;
    newSession.end.tv_sec = header->ts.tv_sec;
    newSession.end.tv_usec = header->ts.tv_usec;
    newSession.ip_src = _ip->ip_src;
    newSession.ip_dst = _ip->ip_dst;
    //cout << inet_ntoa(_ip->ip_src) << "  ";
    //cout << inet_ntoa(_ip->ip_dst) << endl;
    newSession.port_src = _tcp->th_sport;
    newSession.port_dst = _tcp->th_dport;
    //newSession.printSession();
    _sessions.push_back(newSession);
}
void SessionSet::labelSession(vector<alert>& alerts)
{
    for(unsigned long sessionIndex=0; sessionIndex<_sessions.size(); sessionIndex++)
    {
        for(unsigned long alertIndex=0; alertIndex<alerts.size(); alertIndex++)
        {
            if(_sessions[sessionIndex].end.tv_sec > alerts[alertIndex].arrival.tv_sec);
            else if(_sessions[sessionIndex].end.tv_sec < alerts[alertIndex].arrival.tv_sec)break;
            else 
            {
                if(_sessions[sessionIndex].end.tv_usec >= alerts[alertIndex].arrival.tv_usec);
                else if(_sessions[sessionIndex].end.tv_usec < alerts[alertIndex].arrival.tv_usec)break;
            }
            _sessions[sessionIndex].label = alerts[alertIndex].label;
        }
    }
}
void SessionSet::outputSession(string path)
{
    ofstream file;
    file.open(path.c_str(),ios::out);
    vector<session>::iterator se_it = _sessions.begin();
    for(se_it; se_it!=_sessions.end(); se_it++)
    {
        //se_it->printSession();
        file << se_it->outputSession();
    }
}
