using CryptoBase.Abstractions.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.CRC32;
using CryptoBase.Digests.CRC32C;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest
{
	[TestClass]
	public class CRC32Test
	{
		private static void TestCore(IHash hash, string message, string expected)
		{
			Assert.AreEqual(4, hash.Length);
			Assert.AreEqual(1, hash.BlockSize);

			Span<byte> o = new byte[hash.Length];

			hash.Update(Encoding.UTF8.GetBytes(message));
			hash.Reset();

			o.Clear();
			hash.Update(Encoding.UTF8.GetBytes(message));
			hash.GetHash(o);
			Assert.AreEqual(expected, o.ToHex());

			o.Clear();
			hash.UpdateFinal(Encoding.UTF8.GetBytes(message), o);
			Assert.AreEqual(expected, o.ToHex());

			hash.Dispose();
		}

		private static void Test(IHash hash, string message, string expected)
		{
			Assert.AreEqual(@"CRC-32", hash.Name);
			TestCore(hash, message, expected);
		}

		private static void TestC(IHash hash, string message, string expected)
		{
			Assert.AreEqual(@"CRC-32C", hash.Name);
			TestCore(hash, message, expected);
		}

		[TestMethod]
		[DataRow(@"", @"00000000")]
		[DataRow(@"a", @"e8b7be43")]
		[DataRow(@"abc", @"352441c2")]
		[DataRow(@"message digest", @"20159d7f")]
		[DataRow(@"abcdefghijklmnopqrstuvwxyz", @"4c2750bd")]
		[DataRow(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"1fc2e6d2")]
		[DataRow(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"7ca94a72")]
		[DataRow(@"123456789", @"cbf43926")]
		[DataRow(@"The quick brown fox jumps over the lazy dog", @"414fa339")]
		public void CRC32(string message, string expected)
		{
			Test(new Crc32SF(), message, expected);
		}

		[TestMethod]
		[DataRow(@"", @"00000000")]
		[DataRow(@"a", @"c1d04330")]
		[DataRow(@"abc", @"364b3fb7")]
		[DataRow(@"message digest", @"02bd79d0")]
		[DataRow(@"abcdefghijklmnopqrstuvwxyz", @"9ee6ef25")]
		[DataRow(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"a245d57d")]
		[DataRow(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"477a6781")]
		[DataRow(@"123456789", @"e3069283")]
		[DataRow(@"The quick brown fox jumps over the lazy dog", @"22620404")]
		public void CRC32C(string message, string expected)
		{
			TestC(new Crc32CSF(), message, expected);
			if (Crc32CX86.IsSupport)
			{
				TestC(new Crc32CX86(), message, expected);
			}
		}
	}
}
