using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security_Lab3;
using System;
using System.Linq;

namespace RC5Tests
{
    [TestClass]
    public class HelpersTests
    {
        [TestMethod]
        public void RandomType()
        {
            var value = MyRandom.GenerateValues(2097151, 512, 144, 3, 1);
            Assert.IsInstanceOfType(value, typeof(ulong[]));
        }

        [TestMethod]
        public void Random2Values()
        {
            var values = MyRandom.GenerateValues(2097151, 512, 144, 3, 2);
            Assert.IsTrue(values[0] != values[1]);
        }

        [TestMethod]
        public void Random10Values()
        {
            var values = MyRandom.GenerateValues(2097151, 512, 144, 3, 10);

            bool equal = false;
            for (int i = 0; i < values.Length; i++)
                for (int j = i; j < values.Length; j++)
                    if (values[i] == values[j] && i != j)
                    {
                        equal = true;
                        break;
                    }

            Assert.IsFalse(equal);
        }

        [TestMethod]
        public void Random100Values()
        {
            var values = MyRandom.GenerateValues(2097151, 512, 144, 3, 100);

            int period = 0;
            for (int i = 1; i < values.Length; i++)
                if (values[i] == 3)
                {
                    period = i;
                    break;
                }

            Assert.IsTrue(period == 49);
        }

        [TestMethod]
        public void HashSize()
        {
            var hash = MyMD5.GetMD5(Encoding.ASCII.GetBytes("abc"));
            Assert.IsTrue(hash.Length == 32);
        }

        [TestMethod]
        public void HashesEqual()
        {
            var hash1 = MyMD5.GetMD5(Encoding.ASCII.GetBytes("abc"));
            var hash2 = MyMD5.GetMD5(Encoding.ASCII.GetBytes("abc"));
            Assert.IsTrue(hash1 == hash2);
        }

        [TestMethod]
        public void HashesNotEqual()
        {
            var hash1 = MyMD5.GetMD5(Encoding.ASCII.GetBytes("abc"));
            var hash2 = MyMD5.GetMD5(Encoding.ASCII.GetBytes("abd"));
            Assert.IsTrue(hash1 != hash2);
        }
    }
}
