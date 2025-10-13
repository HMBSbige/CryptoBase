using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.MD5;
using System.Text;

namespace CryptoBase.Tests;

public class MD5Test
{
	private static void MD5DigestTest(IHash md5, string str, string md5Str)
	{
		Assert.Equal(@"MD5", md5.Name);
		Assert.Equal(16, md5.Length);
		Assert.Equal(64, md5.BlockSize);

		Span<byte> origin = Encoding.UTF8.GetBytes(str);
		Span<byte> hash = stackalloc byte[md5.Length];

		md5.UpdateFinal(origin, hash);
		md5.UpdateFinal(origin, hash);

		Assert.Equal(md5Str, hash.ToHex());
		md5.Update(origin);
		md5.GetHash(hash);

		Assert.Equal(md5Str, hash.ToHex());

		md5.Update(origin);
		md5.Reset();

		md5.Update(origin[..(origin.Length / 2)]);
		md5.Update(origin[(origin.Length / 2)..]);
		md5.GetHash(hash);

		Assert.Equal(md5Str, hash.ToHex());

		md5.Update(origin[..(origin.Length / 2)]);
		md5.UpdateFinal(origin[(origin.Length / 2)..], hash);

		Assert.Equal(md5Str, hash.ToHex());
		md5.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/rfc1321#appendix-A.5
	/// </summary>
	[Theory]
	[InlineData(@"", @"d41d8cd98f00b204e9800998ecf8427e")]
	[InlineData(@"a", @"0cc175b9c0f1b6a831c399e269772661")]
	[InlineData(@"abc", @"900150983cd24fb0d6963f7d28e17f72")]
	[InlineData(@"message digest", @"f96b697d7cb7938d525a2f31aaf161d0")]
	[InlineData(@"abcdefghijklmnopqrstuvwxyz", @"c3fcd3d76192e4007dfb496cca67e13b")]
	[InlineData(@"中文测试14", @"0958d88b4122b0f1cf13f19ee461b339")]
	[InlineData(@"1234567890123456789012", @"aad9dc90c98e6472bd0b67067b5b11c9")]
	[InlineData(@"32323232323232323232323232323232", @"b9cfdc1fb63d34054bbfebff4e99795a")]
	[InlineData(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012", @"b76972fe0dff4baac395b531646f738e")]
	[InlineData(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"d174ab98d277d9f5a5611c2c9f419d9f")]
	[InlineData(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"57edf4a22be3c955ac49da2e2107b67a")]
	[InlineData(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", @"268c7919189d85e276d74b8c60b2f84f")]
	public void LongMessageTest(string str, string md5Str)
	{
		MD5DigestTest(new DefaultMD5Digest(), str, md5Str);
		MD5DigestTest(new BcMD5Digest(), str, md5Str);
		MD5DigestTest(new MD5Digest(), str, md5Str);
	}

	[Theory(Skip = "Skip LargeMessage", SkipUnless = nameof(TestEnvironment.TestLargeMessage), SkipType = typeof(TestEnvironment))]
	[InlineData(@"euasxpm", @"cb9c2e659941f68ab669d33418d798fa")]
	public void LargeMessageTest(string str, string result)
	{
		TestUtils.LargeMessageTest(new DefaultMD5Digest(), str, result);
		TestUtils.LargeMessageTest(new BcMD5Digest(), str, result);
		TestUtils.LargeMessageTest(new MD5Digest(), str, result);
	}
}
