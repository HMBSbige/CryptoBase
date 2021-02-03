using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class SM4Test
	{
		private static void Test(IBlockCrypto crypto, string hex1, string hex2, string hex3)
		{
			Assert.AreEqual(@"SM4", crypto.Name);
			Assert.AreEqual(16, crypto.BlockSize);

			Span<byte> h1 = hex1.FromHex();
			Span<byte> h2 = hex2.FromHex();
			Span<byte> h3 = hex3.FromHex();
			Span<byte> o1 = new byte[crypto.BlockSize];

			crypto.Encrypt(h1, o1);
			Assert.IsTrue(o1.SequenceEqual(h2));

			crypto.Encrypt(h1, o1);
			Assert.IsTrue(o1.SequenceEqual(h2));

			var t = h1;
			for (var i = 0; i < 1000000; ++i)
			{
				crypto.Encrypt(t, o1);
				t = o1;
			}

			Assert.IsTrue(t.SequenceEqual(h3));

			crypto.Decrypt(h2, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			crypto.Decrypt(h2, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			t = h3;
			for (var i = 0; i < 1000000; ++i)
			{
				crypto.Decrypt(t, o1);
				t = o1;
			}
			Assert.IsTrue(t.SequenceEqual(h1));

			crypto.Dispose();
		}

		[TestMethod]
		[DataRow(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"595298C7C6FD271F0402F804C33D3F66")]
		public void Test(string keyHex, string hex1, string hex2, string hex3)
		{
			var key = keyHex.FromHex();
			Test(new BcSM4Crypto(default, key), hex1, hex2, hex3);
		}
	}
}
