using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Security_Lab3
{
    public static class MyRC5
    {
        private static byte w = 64;
        private static byte r = 20;
        private static byte b = 16;

        private static ulong Pw = 0xB7E151638AED2A6B;
        private static ulong Qw = 0x9E3779B97F4A7C15;

        public static byte[] EncryptCBCPad(byte[] message, string password)
        {
            int v = w / 8 * 2 - (message.Length) % (w * 2 / 8);

            message = message.Concat(Enumerable.Repeat((byte)v, v)).ToArray();

            return EncryptCBC(message, password);
        }

        public static byte[] DecryptCBCPad(byte[] message, string password)
        {
            var decrypted = DecryptCBC(message, password);
            return decrypted.Take(decrypted.Length - decrypted.Last()).ToArray();
        }
    
        public static byte[] EncryptCBC(byte[] message, string password)
        {
            if (message.Length % 16 != 0)
            {
                Console.WriteLine("Troubles.");
                return null;
            }

            var hash = MyMD5.GetMD5(Encoding.ASCII.GetBytes(password)).Remove(16);
            var IV = MyRandom.GenerateValues(2097151, 512, 144, 3, 2);

            List<byte> result = new List<byte>();

            List<byte> encr_IV = new List<byte>();
            encr_IV.AddRange(BitConverter.GetBytes(IV[0]));
            encr_IV.AddRange(BitConverter.GetBytes(IV[1]));

            result.AddRange(EncryptBlockEBC(encr_IV.ToArray(), GetS(Encoding.ASCII.GetBytes(hash))));

            for (int i = 0; i < message.Length / (2 * w / 8); i++)
            {
                byte[] arr = new byte[16];
                Array.Copy(message, 16 * i, arr, 0, 16);

                Array.Copy(BitConverter.GetBytes(IV[0] ^ BitConverter.ToUInt64(arr, 0)), 0, arr, 0, 8);
                Array.Copy(BitConverter.GetBytes(IV[1] ^ BitConverter.ToUInt64(arr, 8)), 0, arr, 8, 8);

                var enc = EncryptBlockEBC(arr, GetS(Encoding.ASCII.GetBytes(hash)));

                result.AddRange(enc);
                IV[0] = BitConverter.ToUInt64(enc, 0);
                IV[1] = BitConverter.ToUInt64(enc, 8);                
            }

            return result.ToArray();
        }

        public static byte[] DecryptCBC(byte[] message, string password)
        {
            byte[] iv = new byte[16];
            Array.Copy(message, 0, iv, 0, 16);

            var hash = MyMD5.GetMD5(Encoding.ASCII.GetBytes(password)).Remove(16);

            iv = DecryptBlockEBC(iv, GetS(Encoding.ASCII.GetBytes(hash)));

            ulong[] IV = new ulong[] { BitConverter.ToUInt64(iv, 0), BitConverter.ToUInt64(iv, 8) };
            
            List<byte> result = new List<byte>();
            
            for (int i = 1; i < message.Length / (2 * w / 8); i++)
            {
                byte[] arr = new byte[16];
                Array.Copy(message, 16 * i, arr, 0, 16);

                var dec = DecryptBlockEBC(arr, GetS(Encoding.ASCII.GetBytes(hash)));

                Array.Copy(BitConverter.GetBytes(IV[0] ^ BitConverter.ToUInt64(dec, 0)), 0, dec, 0, 8);
                Array.Copy(BitConverter.GetBytes(IV[1] ^ BitConverter.ToUInt64(dec, 8)), 0, dec, 8, 8);
                               
                result.AddRange(dec);
                IV[0] = BitConverter.ToUInt64(message, 16 * i);
                IV[1] = BitConverter.ToUInt64(message, 16 * i + 8);
            }

            return result.ToArray();
        }

        public static byte[] EncryptEBC(byte[] message, string password)
        {
            if (message.Length % 16 != 0)
            {
                Console.WriteLine("Troubles.");
                return null;
            }

            var hash = MyMD5.GetMD5(Encoding.ASCII.GetBytes(password)).Remove(16);

            List<byte> result = new List<byte>();

            for(int i = 0; i < message.Length / (2 * w / 8); i++)
            {
                byte[] arr = new byte[16];
                Array.Copy(message, 16 * i, arr, 0, 16);
                result.AddRange(EncryptBlockEBC(arr, GetS(Encoding.ASCII.GetBytes(hash))));
            }

            return result.ToArray();
        }

        public static byte[] EncryptBlockEBC(byte[] block, ulong[] S)
        {
            ulong A = BitConverter.ToUInt64(block, 0);
            ulong B = BitConverter.ToUInt64(block, 8);

            A += S[0];
            B += S[1];

            //var a = BitConverter.GetBytes(A);
            //var b = BitConverter.GetBytes(B);

            for (int i = 1; i <= r; i++)
            {
                A = CLS((A ^ B), B) + S[2 * i];
                B = CLS((B ^ A), A) + S[2 * i + 1];
            }

            List<byte> res = new List<byte>();
            res.AddRange(BitConverter.GetBytes(A));
            res.AddRange(BitConverter.GetBytes(B));

            return res.ToArray();
        }

        public static byte[] DecryptEBC(byte[] message, string password)
        {
            var hash = MyMD5.GetMD5(Encoding.ASCII.GetBytes(password)).Remove(16);

            List<byte> result = new List<byte>();
            for (int i = 0; i < message.Length / (2 * w / 8); i++)
            {
                byte[] arr = new byte[16];
                Array.Copy(message, 16 * i, arr, 0, 16);
                result.AddRange(DecryptBlockEBC(arr, GetS(Encoding.ASCII.GetBytes(hash))));
            }

            return result.ToArray();
        }

        public static byte[] DecryptBlockEBC(byte[] block, ulong[] S)
        {
            ulong A = BitConverter.ToUInt64(block, 0);
            ulong B = BitConverter.ToUInt64(block, 8);

            for(int i = r; i > 0; i--)
            {
                B = CRS((B - S[2 * i + 1]), A) ^ A;
                A = CRS((A - S[2 * i]), B) ^ B;
            }

            A -= S[0];
            B -= S[1];

            List<byte> res = new List<byte>();
            res.AddRange(BitConverter.GetBytes(A));
            res.AddRange(BitConverter.GetBytes(B));

            return res.ToArray();
        }

        public static ulong[] GetS(byte[] K)
        {
            uint u = (uint)w / 8;
            uint c = b / u;
            uint n = 2 * (uint)r + 2;

            ulong[] L = new ulong[c];
            ulong[] S = new ulong[n];

            for (int i = 0, j = 0; i < c; i++, j += 8)
            {
                L[i] = BitConverter.ToUInt64(K, j);
            }

            S[0] = Pw;
            for(int i = 1; i < n; i++)
            {
                S[i] = S[i - 1] + Qw;
            }
                    
            ulong A = 0, B = 0;
            uint t = Math.Max(c, n);
            for (int i = 0, j = 0, s = 0; s < 3 * t; s++)
            {
                A = S[i] = CLS((S[i] + A + B), 3);
                B = L[j] = CLS((L[j] + A + B), (A + B));

                i = (i + 1) % (int)n;
                j = (j + 1) % (int)c;
            }
            
            for (int i = 0; i < n; i++)
            {
                var bb = BitConverter.GetBytes(S[i]);
            }

            return S;
        }

        private static ulong CLS(ulong a, ulong s)
        {
            int ss = (int)(s - 64 * (s / 64));
            return ((a << ss) | (a >> 64 - ss));
        }

        private static ulong CRS(ulong a, ulong s)
        {
            int ss = (int)(s - 64 * (s / 64));
            return ((a >> ss) | (a << 64 - ss));
        }

    }
}
