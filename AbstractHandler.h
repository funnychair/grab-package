#ifndef ABSTRACTHANDLER
#define ABSTRACTHANDLER
#include <vector>
#include "StructSet.h"

using namespace std;

class AbstractHandler
{
public:
    AbstractHandler(int timeout, vector<session> &sessionV): _timeout(timeout), _sessions(sessionV){};
    virtual ~AbstractHandler(){};
protected:
    int _timeout;
    const struct sniff_ethernet *_ethernet;
    const struct sniff_ip *_ip;
    const struct sniff_tcp *_tcp;
    const struct sniff_udp *_udp;
    const struct sniff_icmp *_icmp;
    vector<session> &_sessions;
    virtual void addSession(){};
    virtual void reflashSession(){};
    virtual bool belongToSession(){};
};

#endif
