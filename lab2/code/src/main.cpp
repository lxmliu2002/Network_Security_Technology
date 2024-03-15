#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctime>
#include <unistd.h>
#include "DES.hpp"
#include "RSA.hpp"
#include <random>

using namespace std;

// char *pKey = "lxmliu66";

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

    fd_set cHandleSet;
    struct timeval tv;
    int nRet;
    while (1)
    {
        FD_ZERO(&cHandleSet);
        FD_SET(nSock, &cHandleSet);
        FD_SET(0, &cHandleSet);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        nRet = select(nSock > 0 ? nSock + 1 : 1, &cHandleSet, NULL, NULL, &tv);
        if (nRet < 0)
        {
            cout << "Select ERROR!" << endl;
            break;
        }
        if (0 == nRet)
        {
            continue;
        }
        if (FD_ISSET(nSock, &cHandleSet))
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
                    cout << "Receive message form " << pRemoteName << ": " << strDecryBuffer << endl;
                    cout << "Input \"quit\" to quit!" << endl;
                    if (0 == memcmp("quit", strDecryBuffer, 4))
                    {
                        cout << "Quit!" << endl;
                        break;
                    }
                }
            }
        }
        if (FD_ISSET(0, &cHandleSet))
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
                perror("send");
            }
            else
            {
                if (0 == memcmp("quit", strStdinBuffer, 4))
                {
                    cout << "Quit!" << endl;
                    break;
                }
            }
        }
    }
}

/**
 * @brief Generates a DES key.
 * 
 * @param key The character array to store the generated key.
 */
void GenerateDesKey(char *key)
{
    srand(time(0));

    for (int i = 0; i < 8; ++i)
    {
        int randChar = rand() % (126 - 33 + 1) + 33;
        key[i] = static_cast<char>(randChar);
    }

    key[8] = '\0';
}

int main()
{
chat:
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

        cRsaSection cRsaSection;
        PublicKey cRsaPublicKey = cRsaSection.GetPublicKey();

        if (send(nAcceptSocket, (char *)&cRsaPublicKey, sizeof(PublicKey), 0) != sizeof(PublicKey))
        {
            perror("Send");
            exit(errno);
        }
        else
        {
            cout << "successful send the RSA public key." << endl;
        }
        char *strDesKey = new char[8];
        memset(strDesKey, 0, 8);
        ULONG64 nEncryptDesKey[4];
        if (4 * sizeof(ULONG64) != TotalRecv(nAcceptSocket, (char *)nEncryptDesKey, 4 * sizeof(ULONG64), 0))
        {
            perror("TotalRecv DES key error");
            exit(errno);
        }
        else
        {
            cout << "successful get the DES key." << endl;
            unsigned short *pDesKey = (unsigned short *)strDesKey;
            for (int i = 0; i < 4; i++)
            {
                pDesKey[i] = cRsaSection.Decry(nEncryptDesKey[i]);
            }
        }
        cout << "Begin to chat..." << endl;
        SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), strDesKey);

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
            cout << "Connect Success!" << endl;
            char *strDesKey = new char[8];
            GenerateDesKey(strDesKey);
            cout << "Create DES key success" << endl;
            cout << "Key: " << strDesKey << endl;
            PublicKey cRsaPublicKey;
            if (sizeof(cRsaPublicKey) == TotalRecv(nConnectSocket, (char *)&cRsaPublicKey, sizeof(cRsaPublicKey), 0))
            {
                cout << "Successful get the RSA public Key" << endl;
            }
            else
            {
                perror("Get RSA public key ");
                exit(errno);
            }
            ULONG64 nEncryptDesKey[4];
            unsigned short *pDesKey = (unsigned short *)strDesKey;
            for (int i = 0; i < 4; i++)
            {
                nEncryptDesKey[i] = cRsaSection::Encry(pDesKey[i], cRsaPublicKey);
            }
            if (sizeof(unsigned long long) * 4 != send(nConnectSocket, (char *)nEncryptDesKey, sizeof(unsigned long long) * 4, 0))
            {
                cout << "Send DES key Error" << endl;
                exit(0);
            }
            else
            {
                cout << "Successful send the encrypted DES Key" << endl;
            }
            cout << "Begin to chat..." << endl;
            SecretChat(nConnectSocket, strIpAddr, strDesKey);
        }
        close(nConnectSocket);
    }
    else
    {
        cout << "Invalid mode!" << endl;
        cout << "Please input 's' for server mode or 'c' for client mode." << endl;
        goto chat;
        exit(errno);
    }
    return 0;
}