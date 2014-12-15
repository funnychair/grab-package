#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "poting.h"

using namespace std;

string BasicFeature::service(const unsigned char * packet){

   const struct sniff_ip* _ip;
   const struct sniff_udp* _udp;
   _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
   _udp = (const struct sniff_udp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);

   
   //cout << service << endl;
   switch(PORT_TRA(_udp->th_dport)){
      case 531:
         return "aol";
         

      case 113:
         return "auth";
         

      case 179:
         return "bgp";
         

      case 1761:
         return "cft";
         

      case 13:
         return "daytime";
         
   
      case 9:
         return "discard";
         

      case 53:
         return "domain";
         

      case 7:
         return "echo";
         

      case 520:
         return "efs";
         

      case 79:
         return "finger";
         

      case 21:
         return "ftp";
         

      case 20:
         return "ftp_data";
         

      case 70:
         return "gopher";
         

      case 42:
         return "hostnames";
         

      case 80:
         return "http";
         

      case 2784:
         return "http_2784";
         

      case 443:
         return "http_443";
         

      case 8001:
         return "http_8001";
         

      case 143:
         return "imap4";
         

      case 6660:
         return "IRC";
         

      case 543:
         return "klogin";
         

      case 544:
         return "kshell";
         

      case 389:
         return "ldap";
         

      case 26:
         return "mtp";
         

      case 138:
         return "netbios_dgm";
         

      case 137:
         return "netbios_ns";
         

      case 139:
         return "netbios_ssn";
         

      case 15:
         return "netstat";
         

      case 433:
         return "nnsp";
         

      case 119:
         return "nntp";
         

      case 123:
         return "ntp_u";
         

      case 109:
         return "pop_2";
         

      case 110:
         return "pop_3";
         

      case 35:
         return "printer";
         

      case 5:
         return "remote_job";
         

      case 514:
         return "shell";
         

      case 587:
         return "smtp";
         

      case 1521:
         return "sql_net";
         

      case 22:
         return "ssh";
         

      case 111:
         return "sunrpc";
         

      case 23:
         return "telnet";
         

      case 69:
         return "tftp_u";
         

      case 540:
         return "uucp";
         

      case 117:
         return "uucp_path";
         

      case 175:
         return "vmnet";
         

      case 43:
         return "whois";
         

      case 6000:
         return "X11";
         

      case 210:
         return "Z39_50";
         

    default:
         return "other";
   }
}
int BasicFeature::isurgent(const unsigned char * packet){

   const struct sniff_ip* _ip;
   const struct sniff_tcp* _tcp;
    _ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    _tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + (_ip->ip_vhl & 0x0f)*4);
    char urg_flag = _tcp->th_flags & TH_URG;
    if (urg_flag == TH_URG) 
        return true;
    else 
        return false;
}
