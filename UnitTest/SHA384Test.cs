using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SHA384;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Threading.Tasks;

namespace UnitTest
{
	[TestClass]
	public class SHA384Test
	{
		private static void SHA384DigestTest(IHash sha384, string str, string sha384Str)
		{
			Assert.AreEqual(@"SHA-384", sha384.Name);
			Assert.AreEqual(48, sha384.Length);
			Assert.AreEqual(128, sha384.BlockSize);

			Span<byte> origin = Encoding.UTF8.GetBytes(str);
			Span<byte> hash = stackalloc byte[sha384.Length];

			sha384.UpdateFinal(origin, hash);
			sha384.UpdateFinal(origin, hash);

			Assert.AreEqual(sha384Str, hash.ToHex());

			sha384.Update(origin);
			sha384.GetHash(hash);

			Assert.AreEqual(sha384Str, hash.ToHex());

			sha384.Update(origin);
			sha384.Reset();

			sha384.Update(origin[..(origin.Length / 2)]);
			sha384.Update(origin[(origin.Length / 2)..]);
			sha384.GetHash(hash);

			Assert.AreEqual(sha384Str, hash.ToHex());

			sha384.Update(origin[..(origin.Length / 2)]);
			sha384.UpdateFinal(origin[(origin.Length / 2)..], hash);

			Assert.AreEqual(sha384Str, hash.ToHex());

			sha384.Dispose();
		}

		[TestMethod]
		[DataRow(@"", @"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")]
		[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")]
		[DataRow(@"abc", @"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")]
		[DataRow(@"a", @"54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31")]
		[DataRow(@"abcdbcdecdefdefgefghfghighijhi", @"0eb6af2176a0934e1177b9ac961fb6ad62abbd301db9027f3a627c276ad7d6a028343233863a25e01e1b80ffb2d1f2a4")]
		[DataRow(@"jkijkljklmklmnlmnomnopnopq", @"4bd7b05260ddb6a61e55b8db2034af1c1e0c30c67cd26ccd61df3452f15b1a7a0b0702f06c922fd2eca30022685f6232")]
		[DataRow(@"01234567012345670123456701234567", @"15065855b8e2dffac1d56d0661b7673e0df684096d81b3ca2f1e7c25872a0a6488d7d029a4be1473032934707f412127")]
		public async Task SHA384DigestTest(string str, string expected)
		{
			SHA384DigestTest(new DefaultSHA384Digest(), str, expected);
			SHA384DigestTest(new BcSHA384Digest(), str, expected);

			await TestUtils.TestStreamAsync(new DefaultSHA384Digest(), str, expected);
			await TestUtils.TestStreamAsync(new BcSHA384Digest(), str, expected);
		}

		/// <summary>
		/// https://www.di-mgt.com.au/sha_testvectors.html
		/// </summary>
		[TestMethod]
		[DataRow(@"a", 1000000, @"9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")]
		[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023")]
		public void LargeMessageTest(string raw, int times, string expected)
		{
			TestUtils.LargeMessageTest(new DefaultSHA384Digest(), raw, times, expected);
			TestUtils.LargeMessageTest(new BcSHA384Digest(), raw, times, expected);
		}
	}
}
