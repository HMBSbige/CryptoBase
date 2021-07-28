using CryptoBase.Abstractions.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests;
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
		[DataRow(@"e9ee3d0a4cc14560a54def3b5a34661eaff800cd6cb64b508c6570a4b4fbaee9c66406137d6640bcb73069c74e99fe5c70d769e7a50340158634d3ec32fad9f15b551e43c36d44fab418d4a2e09349edfce7a4f6547d4745aeb9c62a9e903c697d0fd3301d42497890d160be3301cc001e20ef15d9a2457ea52d312fbbea8ea05692c82743ee44aba3d235eb3bddcdb625f1a4177ae3417bb19fd5bc2e80ec10592599598f6046bca94c77ed61ebdd1084a78f5c8878482a9b583258efdf62f6f23a1fddb69f4574950632b4fd10413f1c53337b7aeb4a56b42695f6687a0782", @"48b84b16")]
		public void CRC32(string message, string expected)
		{
			Test(new Crc32SF(), message, expected);
			Test(DigestUtils.Create(DigestType.Crc32), message, expected);
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
		[DataRow(@"e9ee3d0a4cc14560a54def3b5a34661eaff800cd6cb64b508c6570a4b4fbaee9c66406137d6640bcb73069c74e99fe5c70d769e7a50340158634d3ec32fad9f15b551e43c36d44fab418d4a2e09349edfce7a4f6547d4745aeb9c62a9e903c697d0fd3301d42497890d160be3301cc001e20ef15d9a2457ea52d312fbbea8ea05692c82743ee44aba3d235eb3bddcdb625f1a4177ae3417bb19fd5bc2e80ec10592599598f6046bca94c77ed61ebdd1084a78f5c8878482a9b583258efdf62f6f23a1fddb69f4574950632b4fd10413f1c53337b7aeb4a56b42695f6687a0782", @"c9c156ee")]
		public void CRC32C(string message, string expected)
		{
			TestC(new Crc32CSF(), message, expected);
			TestC(DigestUtils.Create(DigestType.Crc32C), message, expected);
		}
	}
}
