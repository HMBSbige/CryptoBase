using CryptoBase;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.MD5;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest
{
	[TestClass]
	public class MD5Test
	{
		private static void MD5DigestTest(IHash md5, string str, string md5Str)
		{
			Assert.AreEqual(@"MD5", md5.Name);
			Assert.AreEqual(16, md5.Length);

			Span<byte> origin = Encoding.UTF8.GetBytes(str);
			Span<byte> hash = stackalloc byte[md5.Length];

			md5.UpdateFinal(origin, hash);
			md5.UpdateFinal(origin, hash);

			Assert.AreEqual(md5Str, hash.ToHex());
			md5.Update(origin);
			md5.GetHash(hash);

			Assert.AreEqual(md5Str, hash.ToHex());

			md5.Update(origin);
			md5.Reset();

			md5.Update(origin.Slice(0, origin.Length / 2));
			md5.Update(origin.Slice(origin.Length / 2));
			md5.GetHash(hash);

			Assert.AreEqual(md5Str, hash.ToHex());

			md5.Update(origin.Slice(0, origin.Length / 2));
			md5.UpdateFinal(origin.Slice(origin.Length / 2), hash);

			Assert.AreEqual(md5Str, hash.ToHex());

			md5.Dispose();
		}

		/// <summary>
		/// https://tools.ietf.org/html/rfc1321#appendix-A.5
		/// </summary>
		[TestMethod]
		[DataRow(@"", @"d41d8cd98f00b204e9800998ecf8427e")]
		[DataRow(@"a", @"0cc175b9c0f1b6a831c399e269772661")]
		[DataRow(@"abc", @"900150983cd24fb0d6963f7d28e17f72")]
		[DataRow(@"message digest", @"f96b697d7cb7938d525a2f31aaf161d0")]
		[DataRow(@"abcdefghijklmnopqrstuvwxyz", @"c3fcd3d76192e4007dfb496cca67e13b")]
		[DataRow(@"中文测试14", @"0958d88b4122b0f1cf13f19ee461b339")]
		[DataRow(@"1234567890123456789012", @"aad9dc90c98e6472bd0b67067b5b11c9")]
		[DataRow(@"32323232323232323232323232323232", @"b9cfdc1fb63d34054bbfebff4e99795a")]
		[DataRow(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012", @"b76972fe0dff4baac395b531646f738e")]
		public void MD5DigestTest(string str, string md5Str)
		{
			MD5DigestTest(new DefaultMD5Digest(), str, md5Str);
			MD5DigestTest(new BcMD5Digest(), str, md5Str);
			MD5DigestTest(new MD5Digest(), str, md5Str);

			Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
			MD5Utils.Fast440(Encoding.UTF8.GetBytes(str), hash);
			Assert.AreEqual(md5Str, hash.ToHex());
		}

		[TestMethod]
		[DataRow(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"d174ab98d277d9f5a5611c2c9f419d9f")]
		[DataRow(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"57edf4a22be3c955ac49da2e2107b67a")]
		[DataRow(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", @"268c7919189d85e276d74b8c60b2f84f")]
		public void LongMessageTest(string str, string md5Str)
		{
			MD5DigestTest(new DefaultMD5Digest(), str, md5Str);
			MD5DigestTest(new BcMD5Digest(), str, md5Str);
			MD5DigestTest(new MD5Digest(), str, md5Str);
		}
	}
}
