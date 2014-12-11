#include "UdpSessionHandler.h"

using namespace std;

UdpSessionHandler::UdpSessionHandler(int timeout, vector<session> &sessionV, const struct pcap_pkthdr *header, const unsigned char *packet) : AbstractHandler(timeout, sessionV)
{
    bool newflag = true;
    for(vector<session>::iterator it = sessionV.begin(); it != sessionV.end(); it++)
    {
        if(belongToSession(header,packet,*it))
        {
            newflag = false;
            reflashSession(header,packet,*it);
            break;
        }
    }
    if(newflag == true)
    {
        addSession(header,packet);
        //cout << "add udp session." << endl;
    }
    //cout << _sessions.size() << endl;
}
UdpSessionHandler::~UdpSessionHandler(){}

void UdpSessionHandler::reflashSession(const struct pcap_pkthdr *header,const unsigned char *packet, session &sess)
{
    //cout << "reflashSession.==" << endl;
    sess.end.tv_sec = header->ts.tv_sec;
    sess.end.tv_usec = header->ts.tv_usec;
    sess.p_number++;
}

void UdpSessionHandler::addSession(const struct pcap_pkthdr *header,const unsigned char *packet)
{
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _udp = (const struct sniff_udp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);

    char *_payload = (char *) (packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4 + 8);

    printf("\n=================================================================\n");
    printf("=================================================================\n");
    printf("============================== UDP ==============================\n");
    printf("=================================================================\n");
    printf("=================================================================\n");

    struct session newSession = {header->ts, _ip->ip_src, _ip->ip_dst};
    newSession.port_src = _udp->th_sport;
    newSession.port_dst = _udp->th_dport;
    newSession.protocol = "udp";
    _sessions.push_back(newSession);
}

bool UdpSessionHandler::belongToSession(const struct pcap_pkthdr *header, const unsigned char *packet, session &sess)
{
    if(sess.protocol!="udp") return false;
    _ip = (const struct sniff_ip*)(packet+SIZE_ETHERNET);
    _udp = (const struct sniff_udp*)(packet+SIZE_ETHERNET+(_ip->ip_vhl & 0x0f)*4);
    if(header->ts.tv_sec > sess.start.tv_sec && header->ts.tv_sec < (sess.end.tv_sec+180))
    {
        if(_ip->ip_src.s_addr==sess.ip_src.s_addr && _ip->ip_dst.s_addr==sess.ip_dst.s_addr)
        {
            if(_udp->th_sport==sess.port_src && _udp->th_dport==sess.port_dst) return true;
        }
        else if(_ip->ip_src.s_addr==sess.ip_dst.s_addr && _ip->ip_dst.s_addr==sess.ip_src.s_addr)
        {
            if(_udp->th_sport==sess.port_dst && _udp->th_dport==sess.port_src) return true;
        }
    }
    else if(header->ts.tv_sec==sess.start.tv_sec && header->ts.tv_usec > sess.start.tv_usec)
    {
        if(_ip->ip_src.s_addr==sess.ip_src.s_addr && _ip->ip_dst.s_addr==sess.ip_dst.s_addr)
        {
            if(_udp->th_sport==sess.port_src && _udp->th_dport==sess.port_dst) return true;
        }
        else if(_ip->ip_src.s_addr==sess.ip_dst.s_addr && _ip->ip_dst.s_addr==sess.ip_src.s_addr)
        {
            if(_udp->th_sport==sess.port_dst && _udp->th_dport==sess.port_src) return true;
        }
    }
    return false;
}

