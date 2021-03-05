using CryptoBase;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SHA1;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest
{
	[TestClass]
	public class SHA1Test
	{
		private static void SHA1DigestTest(IHash sha1, string str, string sha1Str)
		{
			Assert.AreEqual(@"SHA-1", sha1.Name);
			Assert.AreEqual(20, sha1.Length);

			Span<byte> origin = Encoding.UTF8.GetBytes(str);
			Span<byte> hash = stackalloc byte[sha1.Length];

			sha1.UpdateFinal(origin, hash);
			sha1.UpdateFinal(origin, hash);

			Assert.AreEqual(sha1Str, hash.ToHex());

			sha1.Update(origin);
			sha1.GetHash(hash);

			Assert.AreEqual(sha1Str, hash.ToHex());

			sha1.Update(origin);
			sha1.Reset();

			sha1.Update(origin.Slice(0, origin.Length / 2));
			sha1.Update(origin.Slice(origin.Length / 2));
			sha1.GetHash(hash);

			Assert.AreEqual(sha1Str, hash.ToHex());

			sha1.Update(origin.Slice(0, origin.Length / 2));
			sha1.UpdateFinal(origin.Slice(origin.Length / 2), hash);

			Assert.AreEqual(sha1Str, hash.ToHex());
		}

		[TestMethod]
		[DataRow(@"", @"da39a3ee5e6b4b0d3255bfef95601890afd80709")]
		[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"a49b2446a02c645bf419f995b67091253a04a259")]
		[DataRow(@"abc", @"a9993e364706816aba3e25717850c26c9cd0d89d")]
		[DataRow(@"a", @"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8")]
		[DataRow(@"abcdbcdecdefdefgefghfghighijhi", @"f9537c23893d2014f365adf8ffe33b8eb0297ed1")]
		[DataRow(@"jkijkljklmklmnlmnomnopnopq", @"346fb528a24b48f563cb061470bcfd23740427ad")]
		[DataRow(@"01234567012345670123456701234567", @"c729c8996ee0a6f74f4f3248e8957edf704fb624")]
		public void SHA1DigestTest(string str, string sha1Str)
		{
			SHA1DigestTest(new DefaultSHA1Digest(), str, sha1Str);
			SHA1DigestTest(new BcSHA1Digest(), str, sha1Str);
		}
	}
}
