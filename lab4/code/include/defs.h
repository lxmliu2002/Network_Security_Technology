#ifndef  DEFS_H
#define  DEFS_H

#include <iostream>
#include <stdio.h>
#include <error.h>
#include <cstring>
#include <string>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>

using namespace std;

struct TCPConThrParam
{
	string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
};

struct TCPConHostThrParam
{
	string HostIP;
	unsigned HostPort;
};

struct UDPThrParam
{
	string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct UDPScanHostThrParam
{
	string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct TCPSYNThrParam
{
	string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct TCPSYNHostThrParam
{
	string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct TCPFINThrParam
{
	string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct TCPFINHostThrParam
{
	string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct ipicmphdr 
{ 
	struct iphdr ip; 
	struct icmphdr icmp; 
}; 

struct pseudohdr
{  
	unsigned long saddr; 
	unsigned long daddr; 
	char useless; 
	unsigned char protocol; 
	unsigned short length; 
};

#endif
