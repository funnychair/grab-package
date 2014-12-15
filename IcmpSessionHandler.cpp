#include "IcmpSessionHandler.h"

using namespace std;

IcmpSessionHandler::IcmpSessionHandler(int timeout, vector<session> &sessionV, const struct pcap_pkthdr *header, const unsigned char *packet) : AbstractHandler(timeout, sessionV)
{
        addSession(header,packet);
}
IcmpSessionHandler::~IcmpSessionHandler(){}


void IcmpSessionHandler::addSession(const struct pcap_pkthdr *header,const unsigned char *packet)
{
    _ethernet = (const struct sniff_ethernet*)(packet);
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _icmp = (const struct sniff_icmp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
    struct session newSession = {header->ts, _ip->ip_src, _ip->ip_dst};
    newSession.port_src = 0;
    newSession.port_dst = 0;
    newSession.protocol = "icmp";
    newSession.src_bytes += (header->len) - (_ip->ip_vhl & 0x10)*4 - SIZE_ETHERNET - 8;
    _sessions.push_back(newSession);
}

bool IcmpSessionHandler::belongToSession(const struct pcap_pkthdr *header, const struct sniff_ip *ip, session &sess)
{
    if(sess.protocol!="icmp") return false;
    if(header->ts.tv_sec > sess.start.tv_sec && header->ts.tv_sec < (sess.end.tv_sec+180))
    {
        if(ip->ip_src.s_addr==sess.ip_src.s_addr && ip->ip_dst.s_addr==sess.ip_dst.s_addr) return true;
    }
    else if(header->ts.tv_sec==sess.start.tv_sec && header->ts.tv_usec > sess.start.tv_usec)
    {
        if(ip->ip_src.s_addr==sess.ip_src.s_addr && ip->ip_dst.s_addr==sess.ip_dst.s_addr) return true;
    }
    return false;
}
