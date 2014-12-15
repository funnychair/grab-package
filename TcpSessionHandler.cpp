#include "TcpSessionHandler.h"

using namespace std;

TcpSessionHandler::TcpSessionHandler(int timeout, vector<session> &sessionV, const struct pcap_pkthdr *header, const unsigned char *packet) : AbstractHandler(timeout, sessionV)
{
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl&0x0f)*4);
    if((short)(_tcp->th_flags)==2)
    {
        addSession(header,packet);
    }
    else
    {
        for(vector<session>::iterator it = sessionV.begin(); it != sessionV.end(); it++)
        {
            if(belongToSession(header,packet,*it))
            {
                reflashSession(header,packet,*it);
                //cout << "reflash~~~~~~~~~~~~~~~~" << endl;
                break;
            }
        }
    }
    //cout << _sessions.size() << endl;
}
TcpSessionHandler::~TcpSessionHandler(){}

void TcpSessionHandler::reflashSession(const struct pcap_pkthdr *header,const unsigned char *packet, session &sess)
{
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
    //cout << "reflashSession.==" << endl;
    sess.end.tv_sec = header->ts.tv_sec;
    sess.end.tv_usec = header->ts.tv_usec;
    sess.p_number++;
    //src_bytes
    if(_ip->ip_src.s_addr==sess.ip_src.s_addr)
    {
        sess.src_bytes += header->len - (_ip->ip_vhl & 0x0f)*4 - SIZE_ETHERNET - _tcp->th_offx2*4;
    }
    //dst_bytes
    else
    {
        sess.dst_bytes += header->len - (_ip->ip_vhl & 0x0f)*4 - SIZE_ETHERNET - _tcp->th_offx2*4;
    }
    //flags status
    if(((_tcp->th_flags&0x4)==0x4)&&(_ip->ip_src.s_addr==sess.ip_src.s_addr)) sess.flag=RSTO;
    else if(((_tcp->th_flags&0x4)==0x4)&&(_ip->ip_src.s_addr==sess.ip_dst.s_addr)) sess.flag=RSTR;
    else if((sess.flag==S0)&&((_tcp->th_flags&0x12)==0x12)) sess.flag=S1;
    else if((sess.flag==S0)&&((_tcp->th_flags&0x4)==0x4)) sess.flag=REJ;
    else if((sess.flag==S1)&&((_tcp->th_flags&0x1)==0x1)&&(_ip->ip_src.s_addr==sess.ip_src.s_addr)) sess.flag=S2;
    else if((sess.flag==S1)&&((_tcp->th_flags&0x1)==0x1)&&(_ip->ip_src.s_addr==sess.ip_dst.s_addr)) sess.flag=S3;
    else if(sess.flag==S1) sess.flag=S11;
    else if(sess.flag==S11&&(_tcp->th_flags&0x1)==0x1) sess.flag=SF;
}

void TcpSessionHandler::addSession(const struct pcap_pkthdr *header,const unsigned char *packet)
{
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0xf)*4);
    struct session newSession = {header->ts, _ip->ip_src, _ip->ip_dst};
    newSession.port_src = PORT_TRA(_tcp->th_sport);
    newSession.port_dst = PORT_TRA(_tcp->th_dport);
    newSession.protocol = "tcp";
    newSession.flag = S0;
    newSession.src_bytes += header->len - (_ip->ip_vhl & 0x0f)*4 - SIZE_ETHERNET - _tcp->th_offx2*4;

    
    
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
            if(PORT_TRA(_tcp->th_sport)==sess.port_src && PORT_TRA(_tcp->th_dport)==sess.port_dst) return true;
        }
        else if(_ip->ip_src.s_addr==sess.ip_dst.s_addr && _ip->ip_dst.s_addr==sess.ip_src.s_addr)
        {
            if(PORT_TRA(_tcp->th_sport)==sess.port_dst && PORT_TRA(_tcp->th_dport)==sess.port_src) return true;
        }
    }
    else if(header->ts.tv_sec==sess.start.tv_sec && header->ts.tv_usec > sess.end.tv_usec)
    {
        if(_ip->ip_src.s_addr==sess.ip_src.s_addr && _ip->ip_dst.s_addr==sess.ip_dst.s_addr)
        {
            if(PORT_TRA(_tcp->th_sport)==sess.port_src && PORT_TRA(_tcp->th_dport)==sess.port_dst) return true;
        }
        else if(_ip->ip_src.s_addr==sess.ip_dst.s_addr && _ip->ip_dst.s_addr==sess.ip_src.s_addr)
        {
            if(PORT_TRA(_tcp->th_sport)==sess.port_dst && PORT_TRA(_tcp->th_dport)==sess.port_src) return true;
        }
    }
    return false;
}

