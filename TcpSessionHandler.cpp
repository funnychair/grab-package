#include "TcpSessionHandler.h"

using namespace std;

TcpSessionHandler::TcpSessionHandler(int timeout, vector<session> &sessionV, const struct pcap_pkthdr *header, const unsigned char *packet) : AbstractHandler(timeout, sessionV)
{
    bool newflag = true;
    for(vector<session>::iterator it = sessionV.begin(); it != sessionV.end(); it++)
    {
        if(belongToSession(header,packet,*it))
        {
            newflag = false;
            reflashSession(header,packet,*it);
            //cout << "reflash~~~~~~~~~~~~~~~~" << endl;
            break;
        }
    }
    if(newflag == true)
    {
        addSession(header,packet);
        //cout << "add tcp session." << endl;
    }
    //cout << _sessions.size() << endl;
}
TcpSessionHandler::~TcpSessionHandler(){}

void TcpSessionHandler::reflashSession(const struct pcap_pkthdr *header,const unsigned char *packet, session &sess)
{
    //cout << "reflashSession.==" << endl;
    sess.end.tv_sec = header->ts.tv_sec;
    sess.end.tv_usec = header->ts.tv_usec;
    sess.p_number++;
}

void TcpSessionHandler::addSession(const struct pcap_pkthdr *header,const unsigned char *packet)
{
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
    struct session newSession = {header->ts, _ip->ip_src, _ip->ip_dst};
    newSession.port_src = _tcp->th_sport;
    newSession.port_dst = _tcp->th_dport;
    newSession.protocol = "tcp";
    _sessions.push_back(newSession);
}

bool TcpSessionHandler::belongToSession(const struct pcap_pkthdr *header, const unsigned char *packet, session &sess)
{
    if(sess.protocol!="tcp") return false;
    _ip = (const struct sniff_ip*)(packet+SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet+SIZE_ETHERNET+(_ip->ip_vhl & 0x0f)*4);
    if(header->ts.tv_sec > sess.start.tv_sec && header->ts.tv_sec < (sess.end.tv_sec+180))
    {
        if(_ip->ip_src.s_addr==sess.ip_src.s_addr && _ip->ip_dst.s_addr==sess.ip_dst.s_addr)
        {
            if(_tcp->th_sport==sess.port_src && _tcp->th_dport==sess.port_dst) return true;
        }
        else if(_ip->ip_src.s_addr==sess.ip_dst.s_addr && _ip->ip_dst.s_addr==sess.ip_src.s_addr)
        {
            if(_tcp->th_sport==sess.port_dst && _tcp->th_dport==sess.port_src) return true;
        }
    }
    else if(header->ts.tv_sec==sess.start.tv_sec && header->ts.tv_usec > sess.end.tv_usec)
    {
        if(_ip->ip_src.s_addr==sess.ip_src.s_addr && _ip->ip_dst.s_addr==sess.ip_dst.s_addr)
        {
            if(_tcp->th_sport==sess.port_src && _tcp->th_dport==sess.port_dst) return true;
        }
        else if(_ip->ip_src.s_addr==sess.ip_dst.s_addr && _ip->ip_dst.s_addr==sess.ip_src.s_addr)
        {
            if(_tcp->th_sport==sess.port_dst && _tcp->th_dport==sess.port_src) return true;
        }
    }
    return false;
}

