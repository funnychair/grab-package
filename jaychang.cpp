#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "jaychang.h"

using namespace std;
bool inTwoSec(const struct pcap_pkthdr *header, const struct session &ses);
bool isSameHost(const u_char *packet, const struct session &sess);
bool isSameService(const u_char *packet, const struct session &sess);

TrafficFeature::TrafficFeature(const struct pcap_pkthdr *header, const u_char *packet, vector<session> &sessionV)
{
    _count_host = 0;
    _count_srv = 0;
    _count_host_srv = 0;
    for(vector<session>::iterator it=sessionV.begin(); it<sessionV.end(); it++)
    {
        if(inTwoSec(header,*it))
        {
            if(isSameHost(packet,*it))
            {
                _count_host++;
                if(isSameService(packet,*it))
                {
                    _count_srv++;
                    _count_host_srv++;
                }
                else
                {
                }
            }
            else
            {
                if(isSameService(packet,*it))
                {
                    _count_srv++;
                }
            }
        }
    }
};

bool inTwoSec(const struct pcap_pkthdr *header, const struct session &ses)
{
    if(ses.end.tv_sec==header->ts.tv_sec-1)return true;
    else if((ses.end.tv_sec==header->ts.tv_sec)&&(ses.end.tv_usec < header->ts.tv_usec))return true;
    else if((ses.end.tv_sec==header->ts.tv_sec-2)&&(ses.end.tv_usec > header->ts.tv_usec))return true;
    else return false;
};
bool isSameHost(const u_char *packet, const struct session &sess)
{
    const struct sniff_ip *ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    if(ip->ip_dst.s_addr!=sess.ip_src.s_addr)return false;
    else return true;
}
bool isSameService(const u_char *packet, const struct session &sess)
{
    const struct sniff_ip *ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    if(ip->ip_p==0x01)
    {
        if(sess.port_dst==0) return true;
        else return false;
    }
    else
    {
        const struct sniff_tcp *tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (ip->ip_vhl&0x0f)*4);
        if(sess.port_src==tcp->th_dport) return true;
        else return false;
    }
}













