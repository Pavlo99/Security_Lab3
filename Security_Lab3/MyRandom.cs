using System.Collections.Generic;

namespace Security_Lab3
{
    public static class MyRandom
    {
        public static ulong[] GenerateValues(double m, double a, double c, double xo, double n)
        {
            List<ulong> res = new List<ulong>();
            double x = xo;

            res.Add((ulong)x);

            for (int i = 0; i < n; i++)
            {
                x = (a * x + c) % m;

                res.Add((ulong)x);
            }

            return res.ToArray();
        }
    }
}
