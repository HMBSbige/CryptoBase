using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class AESTest
	{
		private static void Test(BlockCryptoBase crypto, string inputHex, string hex)
		{
			Assert.AreEqual(@"AES", crypto.Name);
			Assert.AreEqual(16, crypto.BlockSize);

			Span<byte> input = inputHex.FromHex();
			Span<byte> h1 = hex.FromHex();
			Span<byte> o1 = stackalloc byte[crypto.BlockSize];

			crypto.UpdateBlock(input, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			crypto.UpdateBlock(input, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			crypto.Dispose();
		}

		/// <summary>
		/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
		/// </summary>
		[TestMethod]
		[DataRow(@"000102030405060708090a0b0c0d0e0f", @"00112233445566778899aabbccddeeff", @"69c4e0d86a7b0430d8cdb78070b4c55a")]
		[DataRow(@"000102030405060708090a0b0c0d0e0f1011121314151617", @"00112233445566778899aabbccddeeff", @"dda97ca4864cdfe06eaf70a0ec0d7191")]
		[DataRow(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"00112233445566778899aabbccddeeff", @"8ea2b7ca516745bfeafc49904b496089")]
		public void Test(string keyHex, string inputHex, string hex)
		{
			var key = keyHex.FromHex();
			Test(new BcAESCrypto(true, key), inputHex, hex);
			Test(new BcAESCrypto(false, key), hex, inputHex);
		}
	}
}
