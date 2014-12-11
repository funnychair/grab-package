#ifndef CHEHSUNLIU_H
#define CHEHSUNLIU_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class chehsunliu
{
public:
  static void print_payload(const u_char *payload, int len);
  static void print_hex_ascii_line(const u_char *payload, int len, int offset);
};

#endif

