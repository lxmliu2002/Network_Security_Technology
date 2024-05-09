#include "Scanner.h"
#include "TCPConnectScan.hpp"
#include "TCPFINScan.hpp"
#include "TCPSYNScan.hpp"
#include "UDPScan.hpp"

int main(int argc, char *argv[])
{
    string HostIP;
    unsigned BeginPort, EndPort, LocalHostIP;
    int ret;

    struct TCPConThrParam TCPConParam;
    struct UDPThrParam UDPParam;
    struct TCPSYNThrParam TCPSynParam;
    struct TCPFINThrParam TCPFinParam;

    pthread_t ThreadID;

    char *pTcpCon = {"-c"};
    char *pTcpSyn = {"-s"};
    char *pTcpFin = {"-f"};
    char *pUdp = {"-u"};
    char *pHelp = {"-h"};

    if (argc != 2)
    {
        cout << "Parameter error !" << endl;
        return -1;
    }

    if (!strcmp(pHelp, argv[1]))
    {
        cout << "Scanner: usage: [-h]  --help information" << endl;
        cout << "                [-c]  --TCP connect scan" << endl;
        cout << "                [-s]  --TCP syn scan" << endl;
        cout << "                [-f]  --TCP fin scan" << endl;
        cout << "                [-u]  --UDP scan" << endl;
        return 1;
    }

    cout << "Please input IP address of a Host:";
    cin >> HostIP;

    if (inet_addr(&(HostIP[0])) == INADDR_NONE)
    {
        cout << "IP address wrong!" << endl;
        return -1;
    }

    cout << "Please input the range of port..." << endl;
    cout << "Begin Port:";
    cin >> BeginPort;
    cout << "End Port:";
    cin >> EndPort;

    if (IsPortOK(BeginPort, EndPort))
    {
        cout << "Scan Host " << HostIP << " port " << BeginPort << "~" << EndPort << " ..." << endl;
    }
    else
    {
        cout << "The range of port is wrong !" << endl;
        return -1;
    }

    LocalHostIP = GetLocalHostIP();

    if (Ping(HostIP, LocalHostIP) == false)
    {
        cout << "Ping Host " << HostIP << " failed, stop scan it !" << endl;
        return -1;
    }

    if (!strcmp(pTcpCon, argv[1]))
    {
        cout << "Begin TCP connect scan..." << endl;
        TCPConParam.HostIP = HostIP;
        TCPConParam.BeginPort = BeginPort;
        TCPConParam.EndPort = EndPort;
        ret = pthread_create(&ThreadID, NULL, Thread_TCPconnectScan, &TCPConParam);
        if (ret == -1)
        {
            cout << "Can't create the TCP connect scan thread !" << endl;
            return -1;
        }
        ret = pthread_join(ThreadID, NULL);
        if (ret != 0)
        {
            cout << "call pthread_join function failed !" << endl;
            return -1;
        }
        else
        {
            cout << "TCP Connect Scan finished !" << endl;
            return 0;
        }
    }

    if (!strcmp(pTcpSyn, argv[1]))
    {
        cout << "Begin TCP SYN scan..." << endl;
        TCPSynParam.HostIP = HostIP;
        TCPSynParam.BeginPort = BeginPort;
        TCPSynParam.EndPort = EndPort;
        TCPSynParam.LocalHostIP = LocalHostIP;
        ret = pthread_create(&ThreadID, NULL, Thread_TCPSynScan, &TCPSynParam);
        if (ret == -1)
        {
            cout << "Can't create the TCP SYN scan thread !" << endl;
            return -1;
        }

        ret = pthread_join(ThreadID, NULL);
        if (ret != 0)
        {
            cout << "call pthread_join function failed !" << endl;
            return -1;
        }
        else
        {
            cout << "TCP SYN Scan finished !" << endl;
            return 0;
        }
    }

    if (!strcmp(pTcpFin, argv[1]))
    {
        cout << "Begin TCP FIN scan..." << endl;
        TCPFinParam.HostIP = HostIP;
        TCPFinParam.BeginPort = BeginPort;
        TCPFinParam.EndPort = EndPort;
        TCPFinParam.LocalHostIP = LocalHostIP;
        ret = pthread_create(&ThreadID, NULL, Thread_TCPFinScan, &TCPFinParam);
        if (ret == -1)
        {
            cout << "Can't create the TCP FIN scan thread !" << endl;
            return -1;
        }

        ret = pthread_join(ThreadID, NULL);
        if (ret != 0)
        {
            cout << "call pthread_join function failed !" << endl;
            return -1;
        }
        else
        {
            cout << "TCP FIN Scan finished !" << endl;
            return 0;
        }
    }

    if (!strcmp(pUdp, argv[1]))
    {
        cout << "Begin UDP scan..." << endl;
        UDPParam.HostIP = HostIP;
        UDPParam.BeginPort = BeginPort;
        UDPParam.EndPort = EndPort;
        UDPParam.LocalHostIP = LocalHostIP;
        ret = pthread_create(&ThreadID, NULL, Thread_UDPScan, &UDPParam);
        if (ret == -1)
        {
            cout << "Can't create the UDP scan thread !" << endl;
            return -1;
        }

        ret = pthread_join(ThreadID, NULL);
        if (ret != 0)
        {
            cout << "call pthread_join function failed !" << endl;
            return -1;
        }
        else
        {
            cout << "UDP Scan finished !" << endl;
            return 0;
        }
    }
    return 0;
}