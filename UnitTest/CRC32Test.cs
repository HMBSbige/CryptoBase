using CryptoBase.Abstractions.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests;
using CryptoBase.Digests.CRC32;
using CryptoBase.Digests.CRC32C;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace UnitTest;

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
	[DataRow(@"5c6f1913817f054beaa45c911b141120ad3822a5d1d27c38362b0b0498bc1e82d7806444f7d25b2ac8581626b6c4c37811c3e5a85e6007fc4dce60e9ab257349281db35eeef273ce326942deec8f9f046240e61072b32733e4be09e8753e53a2294b7bd7b3b1474fcd4bafa88ab0c8fc36ce4696ee093e4a3300064303430eff32d41657783a660fe72086f94db23b194b1d96f44283323a67e80e475c1afe08b910a1e2e5c242a5ed33c9a26135a66ecb766e514f20bd4a631d80f886408d7507238f5b505b2cc1df4092f4c400955de89dfc2136bad7e292ba6091c19c64d86cfa6870bb35af7930a730362b0c0deace27b46f48cdccd02231c1f22f8029", @"76472786")]
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
	[DataRow(@"5c6f1913817f054beaa45c911b141120ad3822a5d1d27c38362b0b0498bc1e82d7806444f7d25b2ac8581626b6c4c37811c3e5a85e6007fc4dce60e9ab257349281db35eeef273ce326942deec8f9f046240e61072b32733e4be09e8753e53a2294b7bd7b3b1474fcd4bafa88ab0c8fc36ce4696ee093e4a3300064303430eff32d41657783a660fe72086f94db23b194b1d96f44283323a67e80e475c1afe08b910a1e2e5c242a5ed33c9a26135a66ecb766e514f20bd4a631d80f886408d7507238f5b505b2cc1df4092f4c400955de89dfc2136bad7e292ba6091c19c64d86cfa6870bb35af7930a730362b0c0deace27b46f48cdccd02231c1f22f8029", @"83c1318e")]
	public void CRC32C(string message, string expected)
	{
		TestC(new Crc32CSF(), message, expected);
		TestC(DigestUtils.Create(DigestType.Crc32C), message, expected);
	}
}
