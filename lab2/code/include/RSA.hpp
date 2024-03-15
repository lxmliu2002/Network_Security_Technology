#ifndef RSA_H
#define RSA_H

#include <iostream>
using namespace std;

typedef uint64_t ULONG64;

/**
 * @brief RSA 结构体
 *
 * 用于存储 RSA 算法中的公钥和模数
 */
struct PublicKey
{
    ULONG64 nE; /**< 公钥 */
    ULONG64 nN; /**< 模数 */
};

/**
 * @brief RSA 密钥结构体
 *
 * 该结构体用于存储 RSA 算法所需的密钥信息。
 */
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

/**
 * @class cRsaSection
 * @brief 表示 RSA 加密和解密操作的部分。
 *
 * `cRsaSection`类提供了生成 RSA 密钥、使用 RSA 算法加密和解密数据的功能。
 * 它还包括执行 RSA 加密和解密所需的数学运算的方法。
 */
class cRsaSection
{
public:
    RsaParam m_cParament;
    // CRandom m_cRadom;

    /**
     * @brief cRsaSection 构造函数。
     *
     * @return 无
     */
    cRsaSection();

    /**
     * @brief GetPublicKey函数返回一个PublicKey对象。
     *
     * @return PublicKey 包含nE和nN值的PublicKey对象。
     */
    PublicKey GetPublicKey();

    /**
     * @brief 计算两个数字的模 n 乘法。
     *
     * @param a 第一个数字
     * @param b 第二个数字
     * @param n 模值
     *
     * @return (a % n) * (b % n) % n 的结果
     */
    static ULONG64 MulMod(ULONG64 a, ULONG64 b, ULONG64 n);

    /**
     * @brief 使用 PowMod 算法计算 (base ^ pow) % n 的结果。
     *
     * @param base 基数
     * @param pow 幂
     * @param n 模数
     *
     * @return (base ^ pow) % n 的结果
     */
    static ULONG64 PowMod(ULONG64 base, ULONG64 pow, ULONG64 n);

    /**
     * @brief 对给定数字进行 Rabin-Miller 素性检测。
     *
     * @param n 要测试素性的数字的引用
     *
     * @return 如果数字可能是质数，则为 1，否则为 0
     */
    static long RabinMillerKnl(ULONG64 &n);

    /**
     * @brief 对给定数字进行 Rabin-Miller 素数测试。
     *
     * @param n 要测试素数性质的数字
     * @param loop 测试的迭代次数
     *
     * @return 如果数字绝对是合数，则返回 0，如果可能是质数，则返回 1
     */
    static long RabinMiller(ULONG64 &n, long loop);

    /**
     * @brief 生成指定位数的随机质数。
     *
     * @param bits 用于生成质数的位数
     *
     * @return 生成的随机质数
     */
    static ULONG64 RandomPrime(char bits);

    /**
     * @brief 使用欧几里德算法计算两个数的最大公约数(GCD)。
     *
     * @param p 第一个数的引用
     * @param q 第二个数的引用
     *
     * @return 两个数的最大公约数
     */
    static ULONG64 Gcd(ULONG64 &p, ULONG64 &q);

    /**
     * @brief 计算欧几里德算法以找到模乘逆。
     *
     * @param e 第一个参数
     * @param t_n 第二个参数
     *
     * @return 模乘逆
     */
    static ULONG64 Euclid(ULONG64 e, ULONG64 t_n);

    /**
     * @brief 使用 RSA 算法计算给定无符号短整数值的加密。
     *
     * @param nSorce 要加密的值
     * @param cKey 用于加密的公钥
     *
     * @return 加密后的值
     */
    static ULONG64 Encry(unsigned short nScore, PublicKey &cKey);

    /**
     * @brief 使用RSA加密解密算法对输入值进行解密。
     *
     * @param nSorce 要解密的值
     *
     * @return 解密后的值
     */
    unsigned short Decry(ULONG64 nScore);
};

/**
 * @brief 计算两个数字的模 n 乘法。
 *
 * @param a 第一个数字
 * @param b 第二个数字
 * @param n 模值
 *
 * @return (a % n) * (b % n) % n 的结果
 */
inline ULONG64 cRsaSection::MulMod(ULONG64 a, ULONG64 b, ULONG64 n)
{
    return (a % n) * (b % n) % n;
}

/**
 * @brief 使用 PowMod 算法计算 (base ^ pow) % n 的结果。
 *
 * @param base 基数
 * @param pow 幂
 * @param n 模数
 *
 * @return (base ^ pow) % n 的结果
 */
ULONG64 cRsaSection::PowMod(ULONG64 base, ULONG64 pow, ULONG64 n)
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

/**
 * @brief 对给定数字进行 Rabin-Miller 素性检测。
 *
 * @param n 要测试素性的数字的引用
 *
 * @return 如果数字可能是质数，则为 1，否则为 0
 */
long cRsaSection::RabinMillerKnl(ULONG64 &n)
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

/**
 * @brief 对给定数字进行 Rabin-Miller 素数测试。
 *
 * @param n 要测试素数性质的数字
 * @param loop 测试的迭代次数
 *
 * @return 如果数字绝对是合数，则返回 0，如果可能是质数，则返回 1
 */
long cRsaSection::RabinMiller(ULONG64 &n, long loop = 100)
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

/**
 * @brief 生成指定位数的随机质数。
 *
 * @param bits 用于生成质数的位数
 *
 * @return 生成的随机质数
 */
ULONG64 cRsaSection::RandomPrime(char bits)
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

/**
 * @brief 使用欧几里德算法计算两个数的最大公约数(GCD)。
 *
 * @param p 第一个数的引用
 * @param q 第二个数的引用
 *
 * @return 两个数的最大公约数
 */
ULONG64 cRsaSection::Gcd(ULONG64 &p, ULONG64 &q)
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

/**
 * @brief 计算欧几里德算法以找到模乘逆。
 *
 * @param e 第一个参数
 * @param t_n 第二个参数
 *
 * @return 模乘逆
 */
ULONG64 cRsaSection::Euclid(ULONG64 e, ULONG64 t_n)
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

/**
 * @brief 使用 RSA 算法计算给定无符号短整数值的加密。
 *
 * @param nSorce 要加密的值
 * @param cKey 用于加密的公钥
 *
 * @return 加密后的值
 */
ULONG64 cRsaSection::Encry(unsigned short nSorce, PublicKey &cKey)
{
    return PowMod(nSorce, cKey.nE, cKey.nN);
}

/**
 * @brief 使用RSA加密解密算法对输入值进行解密。
 *
 * @param nSorce 要解密的值
 *
 * @return 解密后的值
 */
unsigned short cRsaSection::Decry(ULONG64 nSorce)
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

/**
 * @brief GetPublicKey函数返回一个PublicKey对象。
 *
 * @return PublicKey 包含nE和nN值的PublicKey对象。
 */
PublicKey cRsaSection::GetPublicKey()
{
    PublicKey cTmp;
    cTmp.nE = this->m_cParament.e;
    cTmp.nN = this->m_cParament.n;
    return cTmp;
}

/**
 * @brief 获取 RSA 参数。
 *
 * @return RsaParam RSA 参数
 */
RsaParam RsaGetParam(void)
{
    RsaParam Rsa = {0};
    ULONG64 t;
    Rsa.p = cRsaSection::RandomPrime(16); // 随机生成两个素数
    Rsa.q = cRsaSection::RandomPrime(16);
    Rsa.n = Rsa.p * Rsa.q;
    Rsa.f = (Rsa.p - 1) * (Rsa.q - 1);
    do
    {
        Rsa.e = rand() % (65536);
        Rsa.e |= 1;
    } while (cRsaSection::Gcd(Rsa.e, Rsa.f) != 1);
    Rsa.d = cRsaSection::Euclid(Rsa.e, Rsa.f);
    Rsa.s = 0;
    t = Rsa.n >> 1;
    while (t)
    {
        Rsa.s++;
        t >>= 1;
    }
    return Rsa;
}

/**
 * @brief cRsaSection 构造函数。
 *
 * @return 无
 */
cRsaSection::cRsaSection()
{
    this->m_cParament = RsaGetParam();
}

#endif // RSA_H