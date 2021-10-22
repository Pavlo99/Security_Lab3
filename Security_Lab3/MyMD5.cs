using System;
using System.Linq;

namespace Security_Lab3
{
    public static class MyMD5
    {
        public static string GetMD5(byte[] input)
        {
            byte[] message = ExtendMessage(input);

            uint A = 0x67452301, B = 0xEFCDAB89, C = 0x98BADCFE, D = 0x10325476;

            byte[] Y = new byte[64];
            for (int q = 0; q < message.Length / 64; q++)
            {
                uint AA = A, BB = B, CC = C, DD = D;

                for (int i = 0; i < 64; i++)
                    Y[i] = message[64 * q + i];

                uint[] X = new uint[16];
                for (int i = 0; i < 16; i++)
                    X[i] = BitConverter.ToUInt32(new byte[] { Y[4 * i], Y[4 * i + 1],
                        Y[4 * i + 2], Y[4 * i + 3] }, 0);

                for (int cycle = 1; cycle <= 4; cycle++)
                {
                    for (int round = 0; round < 16; round++)
                    {
                        A = B + CLS((A + F(cycle, B, C, D) + X[K(cycle, round)] + T(cycle, round)),
                            S(cycle, round));
                        uint tempA = A;
                        A = D;
                        D = C;
                        C = B;
                        B = tempA;
                    }
                }

                A = AA + A;
                B = BB + B;
                C = CC + C;
                D = DD + D;
            }

            string deb = "";
            foreach (var b in BitConverter.GetBytes(A))
                deb += b > 16 ? Convert.ToString(b, 16) : "0" + Convert.ToString(b, 16);
            foreach (var b in BitConverter.GetBytes(B))
                deb += b > 16 ? Convert.ToString(b, 16) : "0" + Convert.ToString(b, 16);
            foreach (var b in BitConverter.GetBytes(C))
                deb += b > 16 ? Convert.ToString(b, 16) : "0" + Convert.ToString(b, 16);
            foreach (var b in BitConverter.GetBytes(D))
                deb += b > 16 ? Convert.ToString(b, 16) : "0" + Convert.ToString(b, 16);
            return deb;
        }

        private static uint CLS(uint a, int s)
        {
            return ((a << s) | (a >> 32 - s));
        }

        private static uint F(int cycle, uint B, uint C, uint D)
        {
            if (cycle == 1)
                return (B & C) | (~B & D);
            if (cycle == 2)
                return (B & D) | (C & ~D);
            if (cycle == 3)
                return B ^ C ^ D;
            return C ^ (B | ~D);
        }

        private static int K(int cycle, int i)
        {
            if (cycle == 1)
                return i;
            if (cycle == 2)
                return (1 + 5 * i) % 16;
            if (cycle == 3)
                return (5 + 3 * i) % 16;
            return 7 * i % 16;
        }

        private static int S(int cycle, int i)
        {
            int[] cycle1 = { 7, 12, 17, 22 };
            int[] cycle2 = { 5, 9, 14, 20 };
            int[] cycle3 = { 4, 11, 16, 23 };
            int[] cycle4 = { 6, 10, 15, 21 };

            if (cycle == 1)
                return cycle1[i % 4];
            if (cycle == 2)
                return cycle2[i % 4];
            if (cycle == 3)
                return cycle3[i % 4];
            return cycle4[i % 4]; ;
        }

        private static uint T(int cycle, int i)
        {
            uint[] T = new uint[] { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                                    0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
                                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,
                                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

            return T[(cycle - 1) * 16 + i];
        }

        private static byte[] ExtendMessage(byte[] input)
        {
            int bytesToAdd = input.Length % 64 < 56 ? 56 - input.Length % 64 : 64 - input.Length % 64 + 56;

            byte[] add = new byte[bytesToAdd];
            add[0] = 0x80;
            byte[] message = input.Concat(add).ToArray();

            ulong len = (ulong)(input.Length * 8 % Math.Pow(2, 64));

            message = message.Concat(BitConverter.GetBytes(len)).ToArray();

            return message;
        }

    }
}
