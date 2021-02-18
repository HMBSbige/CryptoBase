using CryptoBase;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
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

		/// <summary>
		/// https://gchq.github.io/CyberChef/#recipe=SM3(256,64)
		/// </summary>
		[TestMethod]
		[DataRow(@"", @"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")]
		[DataRow(@"abc", @"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")]
		[DataRow(@"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", @"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")]
		[DataRow(@"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", @"f07b76f62b616de94e6ef9733db1953b8e3fa55014c3f4667abf2ea60aa44250")]
		public void SM3DigestTest(string str, string sm3Str)
		{
			SM3DigestTest(new BcSM3Digest(), str, sm3Str);
			SM3DigestTest(new SM3Digest(), str, sm3Str);
		}
	}
}
