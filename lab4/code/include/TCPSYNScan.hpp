#ifndef TCPSYNSCAN_H
#define TCPSYNSCAN_H

#include "defs.h"

#define __FAVOR_BSD

int TCPSynThrdNum;

pthread_mutex_t TCPSynPrintlocker = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TCPSynScanlocker = PTHREAD_MUTEX_INITIALIZER;
extern unsigned short in_cksum(unsigned short *ptr, int nbytes);

void *Thread_TCPSYNHost(void *param)
{
    struct TCPSYNHostThrParam *p;
    string HostIP;
    unsigned HostPort, LocalPort, LocalHostIP;
    int SynSock;
    int len;
    char sendbuf[8192];
    char recvbuf[8192];
    struct sockaddr_in SYNScanHostAddr;
    p = (struct TCPSYNHostThrParam *)param;
    HostIP = p->HostIP;
    HostPort = p->HostPort;
    LocalPort = p->LocalPort;
    LocalHostIP = p->LocalHostIP;
    memset(&SYNScanHostAddr, 0, sizeof(SYNScanHostAddr));
    SYNScanHostAddr.sin_family = AF_INET;
    SYNScanHostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
    SYNScanHostAddr.sin_port = htons(HostPort);
    SynSock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (SynSock < 0)
    {
        pthread_mutex_lock(&TCPSynPrintlocker);
        cout << "Can't creat raw socket !" << endl;
        pthread_mutex_unlock(&TCPSynPrintlocker);
    }
    struct pseudohdr *ptcph = (struct pseudohdr *)sendbuf;
    struct tcphdr *tcph = (struct tcphdr *)(sendbuf + sizeof(struct pseudohdr));
    ptcph->saddr = LocalHostIP;
    ptcph->daddr = inet_addr(&HostIP[0]);
    ptcph->useless = 0;
    ptcph->protocol = IPPROTO_TCP;
    ptcph->length = htons(sizeof(struct tcphdr));
    tcph->th_sport = htons(LocalPort);
    tcph->th_dport = htons(HostPort);
    tcph->th_seq = htonl(123456);
    tcph->th_ack = 0;
    tcph->th_x2 = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;
    tcph->th_urp = 0;
    tcph->th_sum = in_cksum((unsigned short *)ptcph, 20 + 12);
    len = sendto(SynSock, tcph, 20, 0, (struct sockaddr *)&SYNScanHostAddr, sizeof(SYNScanHostAddr));
    if (len < 0)
    {
        pthread_mutex_lock(&TCPSynPrintlocker);
        cout << "Send TCP SYN Packet error !" << endl;
        pthread_mutex_unlock(&TCPSynPrintlocker);
    }
    len = read(SynSock, recvbuf, 8192);
    if (len <= 0)
    {
        pthread_mutex_lock(&TCPSynPrintlocker);
        cout << "Read TCP SYN Packet error !" << endl;
        pthread_mutex_unlock(&TCPSynPrintlocker);
    }
    else
    {
        struct ip *iph = (struct ip *)recvbuf;
        int i = iph->ip_hl * 4;
        struct tcphdr *tcph = (struct tcphdr *)&recvbuf[i];

        string SrcIP = inet_ntoa(iph->ip_src);
        string DstIP = inet_ntoa(iph->ip_dst);
        struct in_addr in_LocalhostIP;
        in_LocalhostIP.s_addr = LocalHostIP;
        string LocalIP = inet_ntoa(in_LocalhostIP);

        unsigned SrcPort = ntohs(tcph->th_sport); 
        unsigned DstPort = ntohs(tcph->th_dport);
        if (HostIP == SrcIP && LocalIP == DstIP && SrcPort == HostPort && DstPort == LocalPort)
        {
            if (tcph->th_flags == TH_SYN || tcph->th_flags == TH_ACK)
            {
                pthread_mutex_lock(&TCPSynPrintlocker);
                cout << "Host: " << SrcIP << " Port: " << ntohs(tcph->th_sport) << " closed !" << endl;
                pthread_mutex_unlock(&TCPSynPrintlocker);
            }
            if (tcph->th_flags == TH_RST)
            {
                pthread_mutex_lock(&TCPSynPrintlocker);
                cout << "Host: " << SrcIP << " Port: " << ntohs(tcph->th_sport) << " open !" << endl;
                pthread_mutex_unlock(&TCPSynPrintlocker);
            }
        }
    }
    delete p;
    close(SynSock);
    pthread_mutex_lock(&TCPSynScanlocker);
    TCPSynThrdNum--;
    pthread_mutex_unlock(&TCPSynScanlocker);
}

void *Thread_TCPSynScan(void *param)
{
    struct TCPSYNThrParam *p;
    string HostIP;
    unsigned BeginPort, EndPort, TempPort, LocalPort, LocalHostIP;
    pthread_t listenThreadID, subThreadID;
    pthread_attr_t attr, lattr;
    int ret;

    p = (struct TCPSYNThrParam *)param;
    HostIP = p->HostIP;
    BeginPort = p->BeginPort;
    EndPort = p->EndPort;
    LocalHostIP = p->LocalHostIP;

    TCPSynThrdNum = 0;
    LocalPort = 1024;

    for (TempPort = BeginPort; TempPort <= EndPort; TempPort++)
    {
        struct TCPSYNHostThrParam *pTCPSYNHostParam = new TCPSYNHostThrParam;
        pTCPSYNHostParam->HostIP = HostIP;
        pTCPSYNHostParam->HostPort = TempPort;
        pTCPSYNHostParam->LocalPort = TempPort + LocalPort;
        pTCPSYNHostParam->LocalHostIP = LocalHostIP;

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        ret = pthread_create(&subThreadID, &attr, Thread_TCPSYNHost, pTCPSYNHostParam);
        if (ret == -1)
        {
            cout << "Can't create the TCP SYN Scan Host thread !" << endl;
        }
        pthread_attr_destroy(&attr);
        pthread_mutex_lock(&TCPSynScanlocker);
        TCPSynThrdNum++;
        pthread_mutex_unlock(&TCPSynScanlocker);
        while (TCPSynThrdNum > 100)
        {
            sleep(3);
        }
    }
    while (TCPSynThrdNum != 0)
    {
        sleep(1);
    }

    cout << "TCP SYN scan thread exit !" << endl;
    pthread_exit(NULL);
}

#endif