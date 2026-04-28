using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SHA1;
using System.Text;

namespace CryptoBase.Tests;

public class SHA1Test
{
	private static async Task SHA1DigestTest_Internal(IHash sha1, string str, string sha1Str)
	{
		await Assert.That(sha1.Name).IsEqualTo(@"SHA-1");
		await Assert.That(sha1.Length).IsEqualTo(20);
		await Assert.That(sha1.BlockSize).IsEqualTo(64);

		byte[] origin = Encoding.UTF8.GetBytes(str);

		byte[] hash = new byte[sha1.Length];

		sha1.UpdateFinal(origin, hash);
		sha1.UpdateFinal(origin, hash);

		await Assert.That(sha1Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha1.Update(origin);
		sha1.GetHash(hash);

		await Assert.That(sha1Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha1.Update(origin);
		sha1.Reset();

		sha1.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sha1.Update(origin.AsSpan().Slice(origin.Length / 2));
		sha1.GetHash(hash);

		await Assert.That(sha1Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha1.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sha1.UpdateFinal(origin.AsSpan().Slice(origin.Length / 2), hash);

		await Assert.That(sha1Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha1.Dispose();
	}

	[Test]
	[Arguments(@"", @"da39a3ee5e6b4b0d3255bfef95601890afd80709")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"a49b2446a02c645bf419f995b67091253a04a259")]
	[Arguments(@"abc", @"a9993e364706816aba3e25717850c26c9cd0d89d")]
	[Arguments(@"a", @"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8")]
	[Arguments(@"abcdbcdecdefdefgefghfghighijhi", @"f9537c23893d2014f365adf8ffe33b8eb0297ed1")]
	[Arguments(@"jkijkljklmklmnlmnomnopnopq", @"346fb528a24b48f563cb061470bcfd23740427ad")]
	[Arguments(@"01234567012345670123456701234567", @"c729c8996ee0a6f74f4f3248e8957edf704fb624")]
	public async Task SHA1DigestTest(string str, string sha1Str)
	{
		await SHA1DigestTest_Internal(new DefaultSHA1Digest(), str, sha1Str);
		await SHA1DigestTest_Internal(new BcSHA1Digest(), str, sha1Str);
	}

	[Test]
	[Arguments(@"a", 1000000, @"34aa973cd4c4daa4f61eeb2bdbad27316534016f")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"7789f0c9ef7bfc40d93311143dfbe69e2017f592")]
	public async Task LargeMessageTest(string raw, int times, string expected)
	{
		await TestUtils.LargeMessageTest(new DefaultSHA1Digest(), raw, times, expected);
		await TestUtils.LargeMessageTest(new BcSHA1Digest(), raw, times, expected);
	}
}
