#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctime>
#include <unistd.h>
#include "DES.hpp"

using namespace std;

char *pKey = "lxmliu66";

#define BUFFERSIZE 64
char strSocketBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];
char strStdinBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];

/**
 * @brief 接收指定长度的数据
 *
 * @param s 套接字描述符
 * @param buf 接收数据的缓冲区指针
 * @param len 接收数据的长度
 * @param flags 接收数据的标志位
 * @return ssize_t 成功接收的数据长度，如果出错则返回-1
 */
ssize_t TotalRecv(int s, void *buf, size_t len, int flags)
{
    size_t nCurSize = 0;
    while (nCurSize < len)
    {
        ssize_t nRes = recv(s, ((char *)buf) + nCurSize, len - nCurSize, flags);
        if (nRes < 0 || nRes + nCurSize > len)
        {
            return -1;
        }
        nCurSize += nRes;
    }
    return nCurSize;
}

/**
 * @brief 实现两个参与方之间的秘密聊天，通过网络连接进行通信
 *
 * @param nSock 网络连接的套接字描述符
 * @param pRemoteName 远程参与方的名称
 * @param pKey 用于安全通信的加密密钥
 */
void SecretChat(int nSock, char *pRemoteName, char *pKey)
{
    CDesOperate cDes;
    if (strlen(pKey) != 8)
    {
        cout << "Key length error";
        exit(errno);
    }
    pid_t nPid;
    nPid = fork();
    if (nPid != 0)
    {
        while (true)
        {
            bzero(&strSocketBuffer, BUFFERSIZE);
            int nLength = 0;
            nLength = TotalRecv(nSock, strSocketBuffer, BUFFERSIZE, 0);
            if (nLength != BUFFERSIZE)
            {
                break;
            }
            else
            {
                int nLen = BUFFERSIZE;
                cDes.Decry(strSocketBuffer, BUFFERSIZE, strDecryBuffer, nLen, pKey, 8);
                strDecryBuffer[BUFFERSIZE - 1] = 0;
                if (strDecryBuffer[0] != 0 && strDecryBuffer[0] != '\n')
                {
                    cout << "Receive message form " << pRemoteName << ": " << strDecryBuffer;
                    cout << "Input \"quit\" to quit" << endl;
                    if (0 == memcmp("quit", strDecryBuffer, 4))
                    {
                        cout << "Quit" << endl;
                        return;
                    }
                }
            }
        }
    }
    else
    {
        while (true)
        {
            bzero(&strStdinBuffer, BUFFERSIZE);
            while (strStdinBuffer[0] == 0)
            {
                if (fgets(strStdinBuffer, BUFFERSIZE, stdin) == NULL)
                {
                    continue;
                }
            }
            int nLen = BUFFERSIZE;
            cDes.Encry(strStdinBuffer, BUFFERSIZE, strEncryBuffer, nLen, pKey, 8);
            if (send(nSock, strEncryBuffer, BUFFERSIZE, 0) != BUFFERSIZE)
            {
                perror("Send");
            }
            else
            {
                if (0 == memcmp("quit", strStdinBuffer, 4))
                {
                    cout << "Quit!" << endl;
                    return;
                }
            }
        }
    }
}

int main()
{
Chat:
    char mode;
    cout << "Client or Server?" << endl;
    cin >> mode;

    // char *pKey;
    // cout << "Please input the key: " << endl;
    // cin >> pKey;
    if (mode == 's')
    {
        cout << "Listening..." << endl;

        int nListenSocket, nAcceptSocket;
        if ((nListenSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            perror("Socket");
            exit(errno);
        }

        struct sockaddr_in sLocalAddr, sRemoteAddr;
        sLocalAddr.sin_family = AF_INET;
        sLocalAddr.sin_port = htons(8888);
        sLocalAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(nListenSocket, (struct sockaddr *)&sLocalAddr, sizeof(struct sockaddr)) == -1)
        {
            perror("Bind");
            exit(errno);
        }
        if (listen(nListenSocket, 5) == -1)
        {
            perror("Listen");
            exit(errno);
        }

        socklen_t nLength;
        nAcceptSocket = accept(nListenSocket, (struct sockaddr *)&sRemoteAddr, &nLength);
        close(nListenSocket);

        cout << "server: got connection from " << inet_ntoa(sRemoteAddr.sin_addr) << ", port ";
        cout << ntohs(sRemoteAddr.sin_port) << " socket " << nAcceptSocket << endl;

        SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), pKey);

        close(nAcceptSocket);
    }
    else if (mode == 'c')
    {
        cout << "Please input the server address:";

        char strIpAddr[16];
        cin >> strIpAddr;

        int nConnectSocket;
        if ((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            perror("Socket");
            exit(errno);
        }

        struct sockaddr_in sDestAddr;
        sDestAddr.sin_family = AF_INET;
        sDestAddr.sin_port = htons(8888);
        sDestAddr.sin_addr.s_addr = inet_addr(strIpAddr);

        if (connect(nConnectSocket, (struct sockaddr *)&sDestAddr, sizeof(struct sockaddr)) != 0)
        {
            perror("Connect");
            exit(errno);
        }
        else
        {
            cout << "Connect Success!" << endl
                      << "Begin to chat.." << endl;
            SecretChat(nConnectSocket, strIpAddr, pKey);
        }
        close(nConnectSocket);
    }
    else
    {
        cout << "Invalid mode! Please try again!" << endl;
        goto Chat;
    }
    return 0;
}
