using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SHA512;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Threading.Tasks;

namespace UnitTest
{
	[TestClass]
	public class SHA512Test
	{
		private static void SHA512DigestTest(IHash sha512, string str, string sha512Str)
		{
			Assert.AreEqual(@"SHA-512", sha512.Name);
			Assert.AreEqual(64, sha512.Length);
			Assert.AreEqual(128, sha512.BlockSize);

			Span<byte> origin = Encoding.UTF8.GetBytes(str);
			Span<byte> hash = stackalloc byte[sha512.Length];

			sha512.UpdateFinal(origin, hash);
			sha512.UpdateFinal(origin, hash);

			Assert.AreEqual(sha512Str, hash.ToHex());

			sha512.Update(origin);
			sha512.GetHash(hash);

			Assert.AreEqual(sha512Str, hash.ToHex());

			sha512.Update(origin);
			sha512.Reset();

			sha512.Update(origin.Slice(0, origin.Length / 2));
			sha512.Update(origin.Slice(origin.Length / 2));
			sha512.GetHash(hash);

			Assert.AreEqual(sha512Str, hash.ToHex());

			sha512.Update(origin.Slice(0, origin.Length / 2));
			sha512.UpdateFinal(origin.Slice(origin.Length / 2), hash);

			Assert.AreEqual(sha512Str, hash.ToHex());

			sha512.Dispose();
		}

		[TestMethod]
		[DataRow(@"", @"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")]
		[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")]
		[DataRow(@"abc", @"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")]
		[DataRow(@"a", @"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75")]
		[DataRow(@"abcdbcdecdefdefgefghfghighijhi", @"6b22632a618b07bc6f18072e60648086a0c3f4220724f737f322606cbacee8ea510dc2970735072ca8e59f185f3a770a8948beb95dfe3bbbe18572ae6ec91f20")]
		[DataRow(@"jkijkljklmklmnlmnomnopnopq", @"f02d8e6b2649207bbfa0ca8fa9a667fc7673f9d23821ae59ac25c3939db9766b301cb61d0b6f56664d3b225b966dedfbf62281f4da7ebda8f13a2e2470a21a76")]
		[DataRow(@"01234567012345670123456701234567", @"f8c0085901bb2e5fc290921c7b08cf9c2e4c305ca417bd18d37fc8e6d5b08c05acedbce6a92c4bc3098c324bf1930ab76aa1dbb3336129006d991ffc8d4a9d09")]
		public async Task SHA512DigestTest(string str, string expected)
		{
			SHA512DigestTest(new DefaultSHA512Digest(), str, expected);
			SHA512DigestTest(new BcSHA512Digest(), str, expected);

			await TestUtils.TestStreamAsync(new DefaultSHA512Digest(), str, expected);
			await TestUtils.TestStreamAsync(new BcSHA512Digest(), str, expected);
		}

		/// <summary>
		/// https://www.di-mgt.com.au/sha_testvectors.html
		/// </summary>
		[TestMethod]
		[DataRow(@"a", 1000000, @"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")]
		[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086")]
		public void LargeMessageTest(string raw, int times, string expected)
		{
			TestUtils.LargeMessageTest(new DefaultSHA512Digest(), raw, times, expected);
			TestUtils.LargeMessageTest(new BcSHA512Digest(), raw, times, expected);
		}
	}
}
