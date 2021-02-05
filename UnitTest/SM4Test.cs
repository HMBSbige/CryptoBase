using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
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

		private static void Test4(IBlockCrypto crypto, string hex1, string hex2)
		{
			Assert.AreEqual(@"SM4", crypto.Name);
			Assert.AreEqual(16, crypto.BlockSize);

			Span<byte> h1 = hex1.FromHex();
			Span<byte> h2 = hex2.FromHex();
			Span<byte> o1 = stackalloc byte[crypto.BlockSize * 4];

			crypto.Encrypt4(h1, o1);
			Assert.IsTrue(o1.SequenceEqual(h2));

			crypto.Encrypt4(h1, o1);
			Assert.IsTrue(o1.SequenceEqual(h2));

			crypto.Dispose();
		}

		[TestMethod]
		[DataRow(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"595298C7C6FD271F0402F804C33D3F66")]
		public void Test(string keyHex, string hex1, string hex2, string hex3)
		{
			var key = keyHex.FromHex();
			Test(new BcSM4Crypto(default, key), hex1, hex2, hex3);
			Test(new SM4Crypto(key), hex1, hex2, hex3);
		}

		[TestMethod]
		[DataRow(@"0123456789ABCDEFFEDCBA9876543210", @"30313233343536373839414243444546464544434241393837363534333231303638314544463334443230363936354538364233453934463533364534323436", @"a3872f02fb1894448052f68afab3f992aaacb41dc85ad1801ec8d1b7fe72cda6b59969760edf908f5df712ee01ff1b867b40773eceacdbd6052380f1764f1ffd")]
		public void Test4(string keyHex, string hex1, string hex2)
		{
			var key = keyHex.FromHex();
			Test4(new BcSM4Crypto(default, key), hex1, hex2);
			Test4(new SM4Crypto(key), hex1, hex2);
		}
	}
}
