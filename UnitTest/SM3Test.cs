using CryptoBase;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.SM3;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest
{
	[TestClass]
	public class SM3Test
	{
		private static void SM3DigestTest(IHash sm3, string str, string sm3Str)
		{
			Assert.AreEqual(@"SM3", sm3.Name);
			Assert.AreEqual(32, sm3.Length);

			var origin = Encoding.UTF8.GetBytes(str);
			Span<byte> hash = stackalloc byte[sm3.Length];

			sm3.ComputeHash(origin, hash);
			sm3.ComputeHash(origin, hash);

			Assert.AreEqual(sm3Str, hash.ToHex());
		}

		[TestMethod]
		[DataRow(@"", @"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")]
		[DataRow(@"abc", @"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")]
		[DataRow(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", @"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")]
		public void SM3DigestTest(string str, string sha1Str)
		{
			SM3DigestTest(new BcSM3Digest(), str, sha1Str);
			SM3DigestTest(new SlowSM3Digest(), str, sha1Str);
		}
	}
}
