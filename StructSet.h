#ifndef STRUCTSET_H
#define STRUCTSET_H
#include <stdint.h>
#include <string>
#include <iostream>
#include <sstream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14

using namespace std;

enum tcpStatus
{
    SYN1,
    SYN2,
    SYN3,
    EST,
    END,
    SYN_ERROR,
    REJ
};

struct session
{
    struct timeval start;
    struct timeval end;
    struct in_addr ip_src,ip_dst;
    u_short port_src,port_dst;
    

    long dur = 0;
    string  protocol;
    unsigned int p_number = 1;
    enum tcpStatus status =  SYN1;
    //TODO: add feature.




    string label = "normal.";
    session(struct timeval time, struct in_addr sip, struct in_addr dip)
    {
        start = end = time;
        ip_src = sip;
        ip_dst = dip;
    }
    void printSession()
    {
        cout << "time=" << start.tv_sec << "--" << end.tv_sec;
        cout << " from=" << setw(16) << inet_ntoa(ip_src) << ":" << setw(6) << port_src;
        cout << " to=" <<setw(16) << inet_ntoa(ip_dst) << ":" << setw(6) << port_dst << "   " << protocol << endl;
    }
    string outputSession()
    {
        std::stringstream ss;
        ss << this->end.tv_sec-this->start.tv_sec << ',' << port_src << ',' << port_dst << ',' << protocol << ',' << p_number << ',' << label << '\n';
        return ss.str();
    }
};

struct alert
{
    struct timeval arrival;
    struct in_addr ip_scr,ip_dst;
    u_short port_src, port_dst;
    string label;
};

struct sniff_ethernet
{
public:
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ip
{
public:
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp
{
public:
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};
struct sniff_udp
{
public:
    u_short th_sport;
    u_short th_dport;
    u_short th_len;
    u_short th_sum;
};
struct sniff_icmp
{
    u_char th_type;
    u_char th_type_code;
    u_short th_sum;
};
#endif
