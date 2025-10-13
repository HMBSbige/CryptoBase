using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using System.Text;

namespace CryptoBase.Tests;

public class SHA224Test
{
	private static void SHA224DigestTest_Internal(IHash sha224, string str, string sha224Str)
	{
		Assert.Equal(@"SHA-224", sha224.Name);
		Assert.Equal(28, sha224.Length);
		Assert.Equal(64, sha224.BlockSize);

		Span<byte> origin = Encoding.UTF8.GetBytes(str);
		Span<byte> hash = stackalloc byte[sha224.Length];

		sha224.UpdateFinal(origin, hash);
		sha224.UpdateFinal(origin, hash);

		Assert.Equal(sha224Str, hash.ToHex());

		sha224.Update(origin);
		sha224.GetHash(hash);

		Assert.Equal(sha224Str, hash.ToHex());

		sha224.Update(origin);
		sha224.Reset();

		sha224.Update(origin[..(origin.Length / 2)]);
		sha224.Update(origin[(origin.Length / 2)..]);
		sha224.GetHash(hash);

		Assert.Equal(sha224Str, hash.ToHex());

		sha224.Update(origin[..(origin.Length / 2)]);
		sha224.UpdateFinal(origin[(origin.Length / 2)..], hash);

		Assert.Equal(sha224Str, hash.ToHex());

		sha224.Dispose();
	}

	[Theory]
	[InlineData(@"", @"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")]
	[InlineData(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")]
	[InlineData(@"abc", @"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")]
	[InlineData(@"a", @"abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5")]
	[InlineData(@"abcdbcdecdefdefgefghfghighijhi", @"92c9be409b247f582a829a5717fc67e233e003ed7ba6f892e9358f01")]
	[InlineData(@"jkijkljklmklmnlmnomnopnopq", @"cae09129d828d03f60ce06115346a7e281cdb198ec61fff40b9ba1db")]
	[InlineData(@"01234567012345670123456701234567", @"71b6560b2f68d8242761a079630eff8e94b882c9c2b16b585672fbcd")]
	public void SHA224DigestTest(string str, string expected)
	{
		SHA224DigestTest_Internal(new BcSHA224Digest(), str, expected);
	}

	/// <summary>
	/// https://www.di-mgt.com.au/sha_testvectors.html
	/// </summary>
	[Theory]
	[InlineData(@"a", 1000000, @"20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67")]
	[InlineData(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85")]
	public void LargeMessageTest(string raw, int times, string expected)
	{
		TestUtils.LargeMessageTest(new BcSHA224Digest(), raw, times, expected);
	}
}
