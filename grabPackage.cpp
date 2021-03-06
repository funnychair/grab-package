#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "SessionSet.h"
#include "AlertSet.h"

/* eTHERNET ADDRESSEs are 6 bytes */
#define ETHER_ADDR_LEN  6
//for ip flag
#define IP_RF 0x8000        // reserved fragment flag 
#define IP_DF 0x4000        // dont fragment flag 
#define IP_MF 0x2000        // MORE FRAGMENTS FLAG 
#define IP_OFFMASK 0x1fff   // mask for fragmenting bits 
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
//for tcp flag
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

// ethernet headers are always exactly 14 bytes //
#define SIZE_ETHERNET 14

using namespace std;

const class sniff_ethernet *ethernet; // The ethernet header //
const class sniff_ip *ip; // The IP header //
const class sniff_tcp *tcp; // The TCP header //
const char *payload; /* Packet payload */
class SessionSet mainSession(180);

//typedef void (*
ofstream finalFile;

u_int size_ip;
u_int size_tcp;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void pcapFile(string);
void pcapDev();

int main(int argc, char *argv[])
{
    
    string pcapDataPath, snortAlertPath, finalDataPath;
    pcapDataPath.assign(argv[1]);
    snortAlertPath.assign(argv[2]);
    finalDataPath.assign(argv[3]);

    finalFile.open(finalDataPath.c_str(), ios::trunc);
    if(!finalFile)
    {
        cout << "open save data fail!\n";
        return 1;
    }

    pcapFile(pcapDataPath);
    //pcapDev();
    
    class AlertSet snortAlert(snortAlertPath);
    vector<alert> alertV = snortAlert.getAlert();
    for(int i=0; i<alertV.size(); i++)
    {
        //cout << (alertV).at(i).label << endl;
    }
    mainSession.setTrafficFeatures();
    mainSession.labelSession(alertV);
    mainSession.outputSession(finalDataPath);
    cout << "======End======" << endl;
    return 0;
}

void pcapFile(string source)
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */

    FILE *dataFile;
    dataFile = fopen (source.c_str(), "r");
    handle = pcap_fopen_offline(dataFile, errbuf);
    if (handle == NULL)
    { 
        fprintf(stderr,"Couldn' open pcap file %s: %s\n", "data", errbuf); 
        return;
    } 
    cout << "==start==" << endl;
    while (packet = pcap_next(handle,&header))
    {
        u_char *pkt_ptr = (u_char*)packet;
        got_packet(NULL, &header, pkt_ptr);
    }
    /* And close the session */
    pcap_close(handle);
    return;
}
void pcapDev()
{
    pcap_t *handle;         /*Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return;
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    cout << "==start==" << endl;
    pcap_loop(handle, 200, got_packet, NULL);
    /* And close the session */
    pcap_close(handle);
    return;
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ethernet = (struct sniff_ethernet*)(packet);
    //check it is IP packet.
    if(ethernet->ether_type==0x08)
    {
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (IP_V(ip)==6) {
            cout << "It is ip version 6." << endl;
            return;
        }
        if(ip->ip_p==0x06||ip->ip_p==0x11||ip->ip_p==0x01)
        {
            mainSession.addPacket(args, header, packet);
        }
        return;
    }
}
