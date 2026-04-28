using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using System.Text;

namespace CryptoBase.Tests;

public class SHA224Test
{
	private static async Task SHA224DigestTest_Internal(IHash sha224, string str, string sha224Str)
	{
		await Assert.That(sha224.Name).IsEqualTo(@"SHA-224");
		await Assert.That(sha224.Length).IsEqualTo(28);
		await Assert.That(sha224.BlockSize).IsEqualTo(64);

		byte[] origin = Encoding.UTF8.GetBytes(str);

		byte[] hash = new byte[sha224.Length];

		sha224.UpdateFinal(origin, hash);
		sha224.UpdateFinal(origin, hash);

		await Assert.That(sha224Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha224.Update(origin);
		sha224.GetHash(hash);

		await Assert.That(sha224Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha224.Update(origin);
		sha224.Reset();

		sha224.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sha224.Update(origin.AsSpan().Slice(origin.Length / 2));
		sha224.GetHash(hash);

		await Assert.That(sha224Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha224.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sha224.UpdateFinal(origin.AsSpan().Slice(origin.Length / 2), hash);

		await Assert.That(sha224Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha224.Dispose();
	}

	[Test]
	[Arguments(@"", @"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")]
	[Arguments(@"abc", @"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")]
	[Arguments(@"a", @"abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5")]
	[Arguments(@"abcdbcdecdefdefgefghfghighijhi", @"92c9be409b247f582a829a5717fc67e233e003ed7ba6f892e9358f01")]
	[Arguments(@"jkijkljklmklmnlmnomnopnopq", @"cae09129d828d03f60ce06115346a7e281cdb198ec61fff40b9ba1db")]
	[Arguments(@"01234567012345670123456701234567", @"71b6560b2f68d8242761a079630eff8e94b882c9c2b16b585672fbcd")]
	public async Task SHA224DigestTest(string str, string expected)
	{
		await SHA224DigestTest_Internal(new BcSHA224Digest(), str, expected);
	}

	/// <summary>
	/// https://www.di-mgt.com.au/sha_testvectors.html
	/// </summary>
	[Test]
	[Arguments(@"a", 1000000, @"20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85")]
	public async Task LargeMessageTest(string raw, int times, string expected)
	{
		await TestUtils.LargeMessageTest(new BcSHA224Digest(), raw, times, expected);
	}
}
