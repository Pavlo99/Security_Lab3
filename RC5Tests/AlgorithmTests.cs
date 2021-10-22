using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security_Lab3;
using System;
using System.Linq;

namespace RC5Tests
{
    [TestClass]
    public class AlgorithmTests
    {
        [TestMethod]
        public void DecryptsBytesEBC16()
        {
            var bytes = Encoding.ASCII.GetBytes("aaaaaaaaaaaaaaaa");
            var c = MyRC5.EncryptEBC(bytes, "password");
            var r = MyRC5.DecryptEBC(c, "password");
            Assert.IsTrue(bytes.SequenceEqual(r));
        }

        [TestMethod]
        public void DecryptsBytesEBC32()
        {
            var bytes = Encoding.ASCII.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            var c = MyRC5.EncryptEBC(bytes, "password");
            var r = MyRC5.DecryptEBC(c, "password");
            Assert.IsTrue(bytes.SequenceEqual(r));
        }

        [TestMethod]
        public void DecryptsBytesEBC32WrongPassword()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var c = MyRC5.EncryptEBC(Encoding.ASCII.GetBytes(message), "password1");
            Assert.AreNotEqual(message, MyRC5.DecryptEBC(c, "password2"));
        }

        [TestMethod]
        public void DecryptsBytesEBC2()
        {
            var message = "aa";
            var c = MyRC5.EncryptEBC(Encoding.ASCII.GetBytes(message), "password");
            Assert.AreEqual(null, c);
        }

        [TestMethod]
        public void DecryptsBase64EBC16()
        {
            var message = "aaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptEBC(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptEBC(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }

        [TestMethod]
        public void DecryptsBase64EBC32()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptEBC(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptEBC(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }

        [TestMethod]
        public void DecryptsBase64EBC32WrongPassword()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptEBC(Encoding.ASCII.GetBytes(message), "password1");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptEBC(Convert.FromBase64String(s), "password2");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsFalse(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBC16()
        {
            var message = "aaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptCBC(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBC(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBC32()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptCBC(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBC(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBC32WrongPassword()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptCBC(Encoding.ASCII.GetBytes(message), "password1");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBC(Convert.FromBase64String(s), "password2");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsFalse(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBC2()
        {
            var message = "aa";
            var c = MyRC5.EncryptEBC(Encoding.ASCII.GetBytes(message), "password");
            Assert.AreEqual(null, c);
        }

        [TestMethod]
        public void DecryptsBase64CBCPad16()
        {
            var message = "aaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptCBCPad(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBCPad(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBCPad32()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptCBCPad(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBCPad(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBCPad32WrongPassword()
        {
            var message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            var c = MyRC5.EncryptCBCPad(Encoding.ASCII.GetBytes(message), "password1");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBCPad(Convert.FromBase64String(s), "password2");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsFalse(r == message);
        }

        [TestMethod]
        public void DecryptsBase64CBCPad2()
        {
            var message = "aa";

            var c = MyRC5.EncryptCBCPad(Encoding.ASCII.GetBytes(message), "password");
            string s = Convert.ToBase64String(c);
            var p = MyRC5.DecryptCBCPad(Convert.FromBase64String(s), "password");
            var r = Encoding.ASCII.GetString(p);

            Assert.IsTrue(r == message);
        }
    }
}
