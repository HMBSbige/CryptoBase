using CryptoBase;
using CryptoBase.Abstractions.Digests;
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

			var origin = Encoding.UTF8.GetBytes(str);
			Span<byte> hash = stackalloc byte[md5.Length];

			md5.ComputeHash(origin, hash);
			md5.ComputeHash(origin, hash);

			Assert.AreEqual(md5Str, hash.ToHex());
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
		[DataRow(@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", @"d174ab98d277d9f5a5611c2c9f419d9f")]
		[DataRow(@"12345678901234567890123456789012345678901234567890123456789012345678901234567890", @"57edf4a22be3c955ac49da2e2107b67a")]
		[DataRow(@"中文测试14", @"0958d88b4122b0f1cf13f19ee461b339")]
		public void MD5DigestTest(string str, string md5Str)
		{
			MD5DigestTest(new NormalMD5Digest(), str, md5Str);
			MD5DigestTest(new BcMD5Digest(), str, md5Str);
			MD5DigestTest(new SlowMD5Digest(), str, md5Str);
		}
	}
}
