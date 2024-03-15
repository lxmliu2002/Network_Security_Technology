#ifndef RSA_H
#define RSA_H

#include <iostream>
using namespace std;

typedef uint64_t ULONG64;

struct PublicKey
{
    ULONG64 nE;
    ULONG64 nN;
};

struct RsaParam
{
    ULONG64 e;
    ULONG64 n;
    ULONG64 d;
    ULONG64 f;
    ULONG64 p;
    ULONG64 q;
    ULONG64 s;
};

// class CRandom
// {
// public:
//     CRandom()
//     {
//         srand((unsigned)time(NULL));
//     }
//     unsigned long Random(unsigned long n)
//     {
//         return rand() % n;
//     }
// };

class CRsaOperate
{
public:
    RsaParam m_cParament;
    // CRandom m_cRadom;
    CRsaOperate();
    PublicKey GetPublicKey();
    static ULONG64 MulMod(ULONG64 a, unsigned long b, unsigned long n);
    static ULONG64 PowMod(ULONG64 base, ULONG64 pow, ULONG64 n);
    static long RabinMillerKnl(ULONG64 &n);
    static long RabinMiller(ULONG64 &n, long loop);
    static ULONG64 RandomPrime(char bits);
    static ULONG64 Gcd(ULONG64 &p, ULONG64 &q);
    static ULONG64 Euclid(ULONG64 e, ULONG64 t_n);
    static ULONG64 Encry(unsigned short nScore, PublicKey &cKey);
    unsigned short Decry(ULONG64 nScore);
};

inline ULONG64 CRsaOperate::MulMod(ULONG64 a, ULONG64 b, ULONG64 n)
{
    return (a % n) * (b % n) % n;
}

ULONG64 CRsaOperate::PowMod(ULONG64 base, ULONG64 pow, ULONG64 n)
{
    ULONG64 a = base, b = pow, c = 1;
    while (b)
    {
        while (!(b & 1))
        {
            b >>= 1;
            a = MulMod(a, a, n);
        }
        b--;
        c = MulMod(a, c, n);
    }
    return c;
}

long CRsaOperate::RabinMillerKnl(ULONG64 &n)
{
    ULONG64 a, q, k, v;
    q = n - 1;
    k = 0;
    while (!(q & 1))
    {
        ++k;
        q >>= 1;
    }
    a = 2 + rand() % (n - 3);
    v = PowMod(a, q, n);
    if (v == 1)
    {
        return 1;
    }

    for (int j = 0; j < k; j++)
    {
        unsigned int z = 1;
        for (int w = 0; w < j; w++)
        {
            z *= 2;
        }
        if (PowMod(a, z * q, n) == n - 1)
        {
            return 1;
        }
    }
    return 0;
}

long CRsaOperate::RabinMiller(ULONG64 &n, long loop = 100)
{
    for (long i = 0; i < loop; i++)
    {
        if (!RabinMillerKnl(n))
        {
            return 0;
        }
    }
    return 1;
}

ULONG64 CRsaOperate::RandomPrime(char bits)
{
    ULONG64 base;
    do
    {
        base = (unsigned long)1 << (bits - 1); // 保证最高位是1
        base += rand() % (base);               // 再加上一个随机数
        base |= 1;                             // 保证最低位是1,即保证是奇数
    } while (!RabinMiller(base, 30));          // 进行拉宾－米勒测试30 次
    return base;                               // 全部通过认为是质数
}

ULONG64 CRsaOperate::Gcd(ULONG64 &p, ULONG64 &q)
{
    ULONG64 a = p > q ? p : q;
    ULONG64 b = p < q ? p : q;
    ULONG64 t;
    if (p == q)
    {
        return p; // 两数相等,最大公约数就是本身
    }
    else
    {
        while (b) // 辗转相除法,gcd(a,b)=gcd(b,a-qb)
        {
            a = a % b;
            t = a;
            a = b;
            b = t;
        }
        return a;
    }
}

ULONG64 CRsaOperate::Euclid(ULONG64 e, ULONG64 t_n)
{
    ULONG64 Max = 0xffffffffffffffff - t_n;
    ULONG64 i = 1;

    while (1)
    {
        if (((i * t_n) + 1) % e == 0)
        {
            return ((i * t_n) + 1) / e;
        }
        i++;
        ULONG64 Tmp = (i + 1) * t_n;
        if (Tmp > Max)
        {
            return 0;
        }
    }
    return 0;
}

ULONG64 CRsaOperate::Encry(unsigned short nSorce, PublicKey &cKey)
{
    return PowMod(nSorce, cKey.nE, cKey.nN);
}

unsigned short CRsaOperate::Decry(ULONG64 nSorce)
{
    ULONG64 nRes = PowMod(nSorce, m_cParament.d, m_cParament.n);
    unsigned short *pRes = (unsigned short *)&(nRes);
    if (pRes[1] != 0 || pRes[3] != 0 || pRes[2] != 0)
    { // error
        return 0;
    }
    else
    {
        return pRes[0];
    }
}

PublicKey CRsaOperate::GetPublicKey()
{
    PublicKey cTmp;
    cTmp.nE = this->m_cParament.e;
    cTmp.nN = this->m_cParament.n;
    return cTmp;
}

RsaParam RsaGetParam(void)
{
    RsaParam Rsa = {0};
    ULONG64 t;
    Rsa.p = CRsaOperate::RandomPrime(16); // 随机生成两个素数
    Rsa.q = CRsaOperate::RandomPrime(16);
    Rsa.n = Rsa.p * Rsa.q;
    Rsa.f = (Rsa.p - 1) * (Rsa.q - 1);
    do
    {
        Rsa.e = rand() % (65536);
        Rsa.e |= 1;
    } while (CRsaOperate::Gcd(Rsa.e, Rsa.f) != 1);
    Rsa.d = CRsaOperate::Euclid(Rsa.e, Rsa.f);
    Rsa.s = 0;
    t = Rsa.n >> 1;
    while (t)
    {
        Rsa.s++;
        t >>= 1;
    }
    return Rsa;
}

CRsaOperate::CRsaOperate()
{
    this->m_cParament = RsaGetParam();
}

#endif // RSA_H