using CryptoBase.Abstractions.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests;
using CryptoBase.Digests.CRC32;
using CryptoBase.Digests.CRC32C;
using System.Text;

namespace CryptoBase.Tests;

public class CRC32Test
{
	private static void TestCore(IHash hash, string message, string expected)
	{
		Assert.Equal(4, hash.Length);
		Assert.Equal(1, hash.BlockSize);

		Span<byte> o = new byte[hash.Length];

		hash.Update(Encoding.UTF8.GetBytes(message));
		hash.Reset();

		o.Clear();
		hash.Update(Encoding.UTF8.GetBytes(message));
		hash.GetHash(o);
		Assert.Equal(expected, o.ToHex());

		o.Clear();
		hash.UpdateFinal(Encoding.UTF8.GetBytes(message), o);
		Assert.Equal(expected, o.ToHex());

		hash.Dispose();
	}

	private static void Test(IHash hash, string message, string expected)
	{
		Assert.Equal(@"CRC-32", hash.Name);
		TestCore(hash, message, expected);
	}

	private static void TestC(IHash hash, string message, string expected)
	{
		Assert.Equal(@"CRC-32C", hash.Name);
		TestCore(hash, message, expected);
	}

	[Theory]
	[InlineData(@"", @"00000000")]
	[InlineData(@"a", @"e8b7be43")]
	[InlineData(@"abc", @"352441c2")]
	[InlineData(@"message digest", @"20159d7f")]
	[InlineData(@"abcdefghijklmnopqrstuvwxyz", @"4c2750bd")]
	[InlineData(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"1fc2e6d2")]
	[InlineData(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"7ca94a72")]
	[InlineData(@"123456789", @"cbf43926")]
	[InlineData(@"The quick brown fox jumps over the lazy dog", @"414fa339")]
	[InlineData(@"5c6f1913817f054beaa45c911b141120ad3822a5d1d27c38362b0b0498bc1e82d7806444f7d25b2ac8581626b6c4c37811c3e5a85e6007fc4dce60e9ab257349281db35eeef273ce326942deec8f9f046240e61072b32733e4be09e8753e53a2294b7bd7b3b1474fcd4bafa88ab0c8fc36ce4696ee093e4a3300064303430eff32d41657783a660fe72086f94db23b194b1d96f44283323a67e80e475c1afe08b910a1e2e5c242a5ed33c9a26135a66ecb766e514f20bd4a631d80f886408d7507238f5b505b2cc1df4092f4c400955de89dfc2136bad7e292ba6091c19c64d86cfa6870bb35af7930a730362b0c0deace27b46f48cdccd02231c1f22f8029", @"76472786")]
	public void CRC32(string message, string expected)
	{
		Test(new Crc32SF(), message, expected);
		Test(DigestUtils.Create(DigestType.Crc32), message, expected);
	}

	[Theory]
	[InlineData(@"", @"00000000")]
	[InlineData(@"a", @"c1d04330")]
	[InlineData(@"abc", @"364b3fb7")]
	[InlineData(@"message digest", @"02bd79d0")]
	[InlineData(@"abcdefghijklmnopqrstuvwxyz", @"9ee6ef25")]
	[InlineData(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"a245d57d")]
	[InlineData(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"477a6781")]
	[InlineData(@"123456789", @"e3069283")]
	[InlineData(@"The quick brown fox jumps over the lazy dog", @"22620404")]
	[InlineData(@"5c6f1913817f054beaa45c911b141120ad3822a5d1d27c38362b0b0498bc1e82d7806444f7d25b2ac8581626b6c4c37811c3e5a85e6007fc4dce60e9ab257349281db35eeef273ce326942deec8f9f046240e61072b32733e4be09e8753e53a2294b7bd7b3b1474fcd4bafa88ab0c8fc36ce4696ee093e4a3300064303430eff32d41657783a660fe72086f94db23b194b1d96f44283323a67e80e475c1afe08b910a1e2e5c242a5ed33c9a26135a66ecb766e514f20bd4a631d80f886408d7507238f5b505b2cc1df4092f4c400955de89dfc2136bad7e292ba6091c19c64d86cfa6870bb35af7930a730362b0c0deace27b46f48cdccd02231c1f22f8029", @"83c1318e")]
	public void CRC32C(string message, string expected)
	{
		TestC(new Crc32CSF(), message, expected);
		TestC(DigestUtils.Create(DigestType.Crc32C), message, expected);
	}
}
