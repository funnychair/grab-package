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
bool inSec(const struct session &target, const struct session &ses, int sec);
bool isSameHost(const struct session &target, const struct session &sess);
bool isSameService(const struct session &target, const struct session &sess);

TrafficFeature::TrafficFeature(vector<session> &sessionV)
{
    vector<session>::iterator itFirst=sessionV.begin();
    itFirst++;
    for(; itFirst!=sessionV.end(); itFirst++)
    {
        _count_srv = 0;
        _count_host = 0;
        _count_srv_REJ = 0;
        _count_srv_SYN = 0;
        _count_host_srv = 0;
        _count_host_REJ = 0;
        _count_host_SYN = 0;
        vector<session>::iterator it=itFirst;
        it--;
        for(; it!=sessionV.begin(); it--)
        {
            if(inSec(*itFirst,*it,100))
            //if(true)
            {
                if(isSameHost(*itFirst,*it))
                {
                    _count_host++;
                    if(isSameService(*itFirst,*it))
                    {
                        _count_srv++;
                        _count_host_srv++;
                        if(it->flag!=SF) _count_srv_SYN++;
                        if(it->flag==REJ) _count_srv_REJ++;
                    }
                    if(it->flag!=SF) _count_host_SYN++;
                    if(it->flag==REJ) _count_host_REJ++;
                }
                else
                {
                    if(isSameService(*itFirst,*it))
                    {
                        _count_srv++;
                        if(it->flag!=SF) _count_srv_SYN++;
                        if(it->flag==REJ) _count_srv_REJ++;
                    }
                }
            }
            else break;
        }
        itFirst->count = _count_host;
        if(itFirst->count!=0)
        {
            itFirst->serror_rate = (float)(_count_host_SYN)/(float)(_count_host);
            itFirst->rerror_rate = (float)(_count_host_REJ)/(float)(_count_host);
            itFirst->same_srv_rate = (float)(_count_host_srv)/(float)(_count_host);
            itFirst->diff_srv_rate = 1 - itFirst->same_srv_rate;
        }
        itFirst->srv_count = _count_srv;
        if(itFirst->srv_count!=0)
        {
            itFirst->srv_serror_rate = (float)(_count_srv_SYN)/(float)(_count_srv);
            itFirst->srv_rerror_rate = (float)(_count_srv_REJ)/(float)(_count_srv);
            itFirst->srv_diff_host_rate = 1-(float)(_count_host_srv)/(float)(_count_srv);
        }
        _count_host = 0;
        _count_srv_REJ = 0;
        _count_srv_SYN = 0;
        _count_host_srv = 0;
        _count_host_REJ = 0;
        _count_host_SYN = 0;
        _count_host_same_src_port = 0;
        _count_host_same_srv_diff_src_host = 0;
        //vector<session>::iterator it2=itFirst;
        it=itFirst;
        it--;
        int i=0;
        for(; it!=sessionV.begin(); it--)
        {
            //cout << "testfffff" << endl;
            if(isSameHost(*itFirst,*it))
            {
                _count_host++;
                if(isSameService(*itFirst,*it))
                {
                    _count_host_srv++;
                    if(it->flag!=SF) _count_srv_SYN++;
                    if(it->flag==REJ) _count_srv_REJ++;
                    if(it->ip_src.s_addr!=itFirst->ip_src.s_addr) _count_host_same_srv_diff_src_host++;
                }
                if(it->flag!=SF) _count_host_SYN++;
                if(it->flag==REJ) _count_host_REJ++;
                if(it->port_src==itFirst->port_src) _count_host_same_src_port++;
            }
            //cout << "dddddddd" << endl;
            i++;
            if(i==100)break;
        }
        itFirst->dst_host_count = _count_host;
        itFirst->dst_host_srv_count = _count_host_srv;
        if(_count_host!=0)
        {
            itFirst->dst_host_same_srv_rate = (float)_count_host_srv/(float)_count_host;
            itFirst->dst_host_diff_srv_rate = 1-itFirst->dst_host_same_srv_rate;
            itFirst->dst_host_same_src_port_rate = (float)_count_host_same_src_port/(float)_count_host;
            itFirst->dst_host_serror_rate = (float)_count_host_SYN/(float)_count_host;
            itFirst->dst_host_rerror_rate = (float)_count_host_REJ/(float)_count_host;
        }
        if(_count_host_srv!=0)
        {
            itFirst->dst_host_srv_diff_host_rate = (float)_count_host_same_srv_diff_src_host/(float)_count_host_srv;
            itFirst->dst_host_srv_serror_rate = (float)_count_srv_SYN/(float)_count_host_srv;
            itFirst->dst_host_srv_rerror_rate = (float)_count_srv_REJ/(float)_count_host_srv;
        }
        //int k = itFirst->srv_count;
        //int k = itFirst->count;
        //float k = itFirst->same_srv_rate;
        //float k = itFirst->dst_host_same_src_port_rate;
        //if(k!=0)
        //{
        //    cout << k << endl;
        //    itFirst->printSession();
        //}
        //itFirst->printSession();
    }
};

bool inSec(const struct session &target, const struct session &ses, int sec)
{
    if(ses.start.tv_sec>target.start.tv_sec-sec)return true;
    else return false;
};
bool isSameHost(const struct session &target, const struct session &sess)
{
    if(target.ip_dst.s_addr!=sess.ip_dst.s_addr)return false;
    else return true;
}
bool isSameService(const struct session &target, const struct session &sess)
{
    if(sess.port_dst==target.port_dst) return true;
    else return false;
}







