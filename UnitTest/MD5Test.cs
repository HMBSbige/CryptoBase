using CryptoBase;
using CryptoBase.Digests;
using CryptoBase.Digests.MD5;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace UnitTest
{
	[TestClass]
	public class MD5Test
	{
		private static void MD5DigestTest(IHash md5, string str, string md5Str)
		{
			Assert.AreEqual(@"MD5", md5.Name);

			var origin = Encoding.UTF8.GetBytes(str);

			var hash = md5.Compute(origin);

			Assert.AreEqual(md5Str, hash.ToHex());
		}

		[TestMethod]
		[DataRow(@"", @"d41d8cd98f00b204e9800998ecf8427e")]
		[DataRow(@"1145141919810", @"32150285b345c48aa3492f9212f61ca2")]
		[DataRow(@"中文测试", @"089b4943ea034acfa445d050c7913e55")]
		public void MD5DigestTest(string str, string md5Str)
		{
			MD5DigestTest(new NormalMD5Digest(), str, md5Str);
			MD5DigestTest(new BcMD5Digest(), str, md5Str);
		}
	}
}
