using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.MD5;
using System.Text;

namespace CryptoBase.Tests;

public class MD5Test
{
	private static async Task MD5DigestTest(IHash md5, string str, string md5Str)
	{
		await Assert.That(md5.Name).IsEqualTo(@"MD5");
		await Assert.That(md5.Length).IsEqualTo(16);
		await Assert.That(md5.BlockSize).IsEqualTo(64);

		byte[] origin = Encoding.UTF8.GetBytes(str);

		byte[] hash = new byte[md5.Length];

		md5.UpdateFinal(origin, hash);
		md5.UpdateFinal(origin, hash);

		await Assert.That(md5Str.SequenceEqual(hash.ToHex())).IsTrue();
		md5.Update(origin);
		md5.GetHash(hash);

		await Assert.That(md5Str.SequenceEqual(hash.ToHex())).IsTrue();

		md5.Update(origin);
		md5.Reset();

		md5.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		md5.Update(origin.AsSpan().Slice(origin.Length / 2));
		md5.GetHash(hash);

		await Assert.That(md5Str.SequenceEqual(hash.ToHex())).IsTrue();

		md5.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		md5.UpdateFinal(origin.AsSpan().Slice(origin.Length / 2), hash);

		await Assert.That(md5Str.SequenceEqual(hash.ToHex())).IsTrue();
		md5.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/rfc1321#appendix-A.5
	/// </summary>
	[Test]
	[Arguments(@"", @"d41d8cd98f00b204e9800998ecf8427e")]
	[Arguments(@"a", @"0cc175b9c0f1b6a831c399e269772661")]
	[Arguments(@"abc", @"900150983cd24fb0d6963f7d28e17f72")]
	[Arguments(@"message digest", @"f96b697d7cb7938d525a2f31aaf161d0")]
	[Arguments(@"abcdefghijklmnopqrstuvwxyz", @"c3fcd3d76192e4007dfb496cca67e13b")]
	[Arguments(@"中文测试14", @"0958d88b4122b0f1cf13f19ee461b339")]
	[Arguments(@"1234567890123456789012", @"aad9dc90c98e6472bd0b67067b5b11c9")]
	[Arguments(@"32323232323232323232323232323232", @"b9cfdc1fb63d34054bbfebff4e99795a")]
	[Arguments(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012", @"b76972fe0dff4baac395b531646f738e")]
	[Arguments(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"d174ab98d277d9f5a5611c2c9f419d9f")]
	[Arguments(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"57edf4a22be3c955ac49da2e2107b67a")]
	[Arguments(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", @"268c7919189d85e276d74b8c60b2f84f")]
	public async Task LongMessageTest(string str, string md5Str)
	{
		await MD5DigestTest(new DefaultMD5Digest(), str, md5Str);
		await MD5DigestTest(new BcMD5Digest(), str, md5Str);
		await MD5DigestTest(new MD5Digest(), str, md5Str);
	}

	[Test]
	[SkipLargeMessage]
	[Arguments(@"euasxpm", @"cb9c2e659941f68ab669d33418d798fa")]
	public async Task LargeMessageTest(string str, string result)
	{
		await TestUtils.LargeMessageTest(new DefaultMD5Digest(), str, result);
		await TestUtils.LargeMessageTest(new BcMD5Digest(), str, result);
		await TestUtils.LargeMessageTest(new MD5Digest(), str, result);
	}
}
