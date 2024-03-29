#ifndef MD5_H
#define MD5_H

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cmath>

using namespace std;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))                // F function
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))                // G function
#define H(x, y, z) ((x) ^ (y) ^ (z))                           // H function
#define I(x, y, z) ((y) ^ ((x) | (~z)))                        // I function
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n)))) // 32 bit num x cycle left shift

#define FF(a, b, c, d, x, s, ac)            \
    {                                       \
        (a) += F((b), (c), (d)) + (x) + ac; \
        (a) = ROTATE_LEFT((a), (s));        \
        (a) += (b);                         \
    }
#define GG(a, b, c, d, x, s, ac)            \
    {                                       \
        (a) += G((b), (c), (d)) + (x) + ac; \
        (a) = ROTATE_LEFT((a), (s));        \
        (a) += (b);                         \
    }
#define HH(a, b, c, d, x, s, ac)            \
    {                                       \
        (a) += H((b), (c), (d)) + (x) + ac; \
        (a) = ROTATE_LEFT((a), (s));        \
        (a) += (b);                         \
    }
#define II(a, b, c, d, x, s, ac)            \
    {                                       \
        (a) += I((b), (c), (d)) + (x) + ac; \
        (a) = ROTATE_LEFT((a), (s));        \
        (a) += (b);                         \
    }

#define T(i) 4294967296 * abs(sin(i))

typedef unsigned char BYTE;
typedef uint32_t DWORD;

class MD5
{
public:
    MD5();
    MD5(const string &str);
    MD5(ifstream &in);
    void Update(const BYTE *input, size_t length); // 对给定长度的输入流进行 MD5 运算
    void Update(const string &str);                // 对给定长度的字符串进行 MD5 运算
    void Update(ifstream &in);                     // 对文件中的内容进行 MD5 运算
    const BYTE *GetDigest();                       // 将 MD5 摘要以字节流形式输出
    string Tostring();                             // 将 MD5 摘要以字符串形式输出
    void Reset();                                  // 重置初始变量

private:
    void Stop();                                                  // 用于终止摘要计算过程，输出摘要
    void Transform(const BYTE block[64]);                         // 对消息分组进行 MD5 计算
    void Encode(const DWORD *input, BYTE *output, size_t length); // 将双字流转换为字节流
    void Decode(const BYTE *input, DWORD *output, size_t length); // 将字节流转换为双字流
    string BytesToHexString(const BYTE *input, size_t length);    // 将字节流按照十六进制字符串形式输出

    DWORD state[4];        // 用于表示 4 个初始向量
    DWORD count[2];        // 用于计数，count[0] 表示低位，count[1] 表示高位
    BYTE buffer_block[64]; // 用于保存计算过程中按块划分后剩下的比特流
    BYTE digest[16];       // 用于保存 128 比特长度的摘要
    bool is_finished;      // 用于标志摘要计算过程是否结束

    static const BYTE padding[64]; // 用于保存消息后面填充的数据块
    static const char hex[16];     // 用于保存 16 进制的字符
};

const BYTE MD5::padding[64] = {0x80};
const char MD5::hex[16] = {
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f'};

MD5::MD5()
{
    Reset();
}

MD5::MD5(const string &str)
{
    Reset();
    Update(str);
}

MD5::MD5(ifstream &in)
{
    Reset();
    Update(in);
}

void MD5::Update(const BYTE *input, size_t length)
{
    DWORD i, index, partLen;
    is_finished = false;                     // 设置停止标识
    index = (DWORD)((count[0] >> 3) & 0x3f); // 计算 buffer 已经存放的字节数

    // 更新计数器 count，将新数据流的长度加上计数器原有的值
    if ((count[0] += ((DWORD)length << 3)) < ((DWORD)length << 3)) // 判断是否进位
    {
        count[1]++;
    }
    count[1] += ((DWORD)length >> 29);

    partLen = 64 - index; // 求出 buffer 中剩余的长度

    // 将数据块逐块进行 MD5 运算
    if (length >= partLen)
    {
        memcpy(&buffer_block[index], input, partLen);
        Transform(buffer_block);
        for (i = partLen; i + 63 < length; i += 64)
        {
            Transform(&input[i]);
        }
        index = 0;
    }
    else
    {
        i = 0;
    }
    memcpy(&buffer_block[index], &input[i], length - i); // 将不足 64 字节的数据复制到 buffer_block 中
}

void MD5::Update(const string &str)
{
    Update((const BYTE *)str.c_str(), str.length());
}

void MD5::Update(ifstream &in)
{
    streamsize length;
    char buffer[1024];
    while (!in.eof())
    {
        in.read(buffer, 1024);
        length = in.gcount();
        if (length > 0)
        {
            Update((const BYTE *)buffer, length);
        }
    }
    in.close();
}

string MD5::Tostring()
{
    return BytesToHexString(GetDigest(), 16);
}

const BYTE *MD5::GetDigest()
{
    if (!this->is_finished)
    {
        this->is_finished = true;
        Stop();
    }
    return this->digest;
}

void MD5::Reset()
{
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
    count[0] = 0;
    count[1] = 0;
    memset(buffer_block,0,64);
    memset(digest,0,16);
    is_finished = false;
}

void MD5::Stop()
{
    BYTE bits[8];
    DWORD tmp_state[4];
    DWORD tmp_count[2];

    memcpy(tmp_state, state, 16);
    memcpy(tmp_count, count, 8);
    Encode(count, bits, 8);

    DWORD index = (count[0] / 8) % 64;
    DWORD padLen;
    if (index < 56)
    {
        padLen = 56 - index;
    }
    else
    {
        padLen = 120 - index;
    }

    Update(padding, padLen);
    Update(bits, 8);
    Encode(state, digest, 16);
    memcpy(state, tmp_state, 16);
    memcpy(count, tmp_count, 8);
}

void MD5::Transform(const BYTE block[64])
{
    DWORD a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    Decode(block, x, 64);

    /* 第 1 轮 */
    FF(a, b, c, d, x[0], 7, T(1));
    FF(d, a, b, c, x[1], 12, T(2));
    FF(c, d, a, b, x[2], 17, T(3));
    FF(b, c, d, a, x[3], 22, T(4));
    FF(a, b, c, d, x[4], 7, T(5));
    FF(d, a, b, c, x[5], 12, T(6));
    FF(c, d, a, b, x[6], 17, T(7));
    FF(b, c, d, a, x[7], 22, T(8));
    FF(a, b, c, d, x[8], 7, T(9));
    FF(d, a, b, c, x[9], 12, T(10));
    FF(c, d, a, b, x[10], 17, T(11));
    FF(b, c, d, a, x[11], 22, T(12));
    FF(a, b, c, d, x[12], 7, T(13));
    FF(d, a, b, c, x[13], 12, T(14));
    FF(c, d, a, b, x[14], 17, T(15));
    FF(b, c, d, a, x[15], 22, T(16));

    /* 第 2 轮 */
    GG(a, b, c, d, x[1], 5, T(17));
    GG(d, a, b, c, x[6], 9, T(18));
    GG(c, d, a, b, x[11], 14, T(19));
    GG(b, c, d, a, x[0], 20, T(20));
    GG(a, b, c, d, x[5], 5, T(21));
    GG(d, a, b, c, x[10], 9, T(22));
    GG(c, d, a, b, x[15], 14, T(23));
    GG(b, c, d, a, x[4], 20, T(24));
    GG(a, b, c, d, x[9], 5, T(25));
    GG(d, a, b, c, x[14], 9, T(26));
    GG(c, d, a, b, x[3], 14, T(27));
    GG(b, c, d, a, x[8], 20, T(28));
    GG(a, b, c, d, x[13], 5, T(29));
    GG(d, a, b, c, x[2], 9, T(30));
    GG(c, d, a, b, x[7], 14, T(31));
    GG(b, c, d, a, x[12], 20, T(32));

    // /* 第 3 轮 */
    HH(a, b, c, d, x[5], 4, T(33));
    HH(d, a, b, c, x[8], 11, T(34));
    HH(c, d, a, b, x[11], 16, T(35));
    HH(b, c, d, a, x[14], 23, T(36));
    HH(a, b, c, d, x[1], 4, T(37));
    HH(d, a, b, c, x[4], 11, T(38));
    HH(c, d, a, b, x[7], 16, T(39));
    HH(b, c, d, a, x[10], 23, T(40));
    HH(a, b, c, d, x[13], 4, T(41));
    HH(d, a, b, c, x[0], 11, T(42));
    HH(c, d, a, b, x[3], 16, T(43));
    HH(b, c, d, a, x[6], 23, T(44));
    HH(a, b, c, d, x[9], 4, T(45));
    HH(d, a, b, c, x[12], 11, T(46));
    HH(c, d, a, b, x[15], 16, T(47));
    HH(b, c, d, a, x[2], 23, T(48));

    // /* 第 4 轮 */
    II(a, b, c, d, x[0], 6, T(49));
    II(d, a, b, c, x[7], 10, T(50));
    II(c, d, a, b, x[14], 15, T(51));
    II(b, c, d, a, x[5], 21, T(52));
    II(a, b, c, d, x[12], 6, T(53));
    II(d, a, b, c, x[3], 10, T(54));
    II(c, d, a, b, x[10], 15, T(55));
    II(b, c, d, a, x[1], 21, T(56));
    II(a, b, c, d, x[8], 6, T(57));
    II(d, a, b, c, x[15], 10, T(58));
    II(c, d, a, b, x[6], 15, T(59));
    II(b, c, d, a, x[13], 21, T(60));
    II(a, b, c, d, x[4], 6, T(61));
    II(d, a, b, c, x[11], 10, T(62));
    II(c, d, a, b, x[2], 15, T(63));
    II(b, c, d, a, x[9], 21, T(64));

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5::Encode(const DWORD *input, BYTE *output, size_t length)
{
    for (size_t i = 0; i * 4 < length; i++)
    {
        for (size_t k = 0; k < 4; k++)
        {
            output[i * 4 + k] = (BYTE)((input[i] >> (k * 8)) & 0xff);
        }
    }
}

void MD5::Decode(const BYTE *input, DWORD *output, size_t length)
{
    const BYTE *inputPtr = input;
    const BYTE *inputEnd = input + length;

    while (inputPtr < inputEnd)
    {
        *output = *((const DWORD *)inputPtr);
        output++;
        inputPtr += sizeof(DWORD);
    }
}

string MD5::BytesToHexString(const BYTE *input, size_t length)
{
    string tmp;
    for (size_t i = 0; i < length; i++)
    {
        int t = input[i];
        int a = t / 16;
        int b = t % 16;
        tmp.append(1, hex[a]);
        tmp.append(1, hex[b]);
    }
    return tmp;
}

#endif // MD5_H