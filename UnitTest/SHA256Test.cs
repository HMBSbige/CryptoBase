using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SHA256;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace UnitTest;

[TestClass]
public class SHA256Test
{
	private static void SHA256DigestTest(IHash sha256, string str, string sha256Str)
	{
		Assert.AreEqual(@"SHA-256", sha256.Name);
		Assert.AreEqual(32, sha256.Length);
		Assert.AreEqual(64, sha256.BlockSize);

		Span<byte> origin = Encoding.UTF8.GetBytes(str);
		Span<byte> hash = stackalloc byte[sha256.Length];

		sha256.UpdateFinal(origin, hash);
		sha256.UpdateFinal(origin, hash);

		Assert.AreEqual(sha256Str, hash.ToHex());

		sha256.Update(origin);
		sha256.GetHash(hash);

		Assert.AreEqual(sha256Str, hash.ToHex());

		sha256.Update(origin);
		sha256.Reset();

		sha256.Update(origin[..(origin.Length / 2)]);
		sha256.Update(origin[(origin.Length / 2)..]);
		sha256.GetHash(hash);

		Assert.AreEqual(sha256Str, hash.ToHex());

		sha256.Update(origin[..(origin.Length / 2)]);
		sha256.UpdateFinal(origin[(origin.Length / 2)..], hash);

		Assert.AreEqual(sha256Str, hash.ToHex());

		sha256.Dispose();
	}

	[TestMethod]
	[DataRow(@"", @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
	[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")]
	[DataRow(@"abc", @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
	[DataRow(@"a", @"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")]
	[DataRow(@"abcdbcdecdefdefgefghfghighijhi", @"d578bbee0ee183a94170d4ff398cb29d06079a65101400771231f3fbb117c999")]
	[DataRow(@"jkijkljklmklmnlmnomnopnopq", @"fb29fa721adddc89b7b58e1c6a5577359f7e879c48672275617fe11ceb851d57")]
	[DataRow(@"01234567012345670123456701234567", @"dd0145169440e7e5c0347ab0c1b4f8c970e6ad3ff625a2edfc52878f384e7681")]
	public void SHA256DigestTest(string str, string sha256Str)
	{
		SHA256DigestTest(new DefaultSHA256Digest(), str, sha256Str);
		SHA256DigestTest(new BcSHA256Digest(), str, sha256Str);
	}

	/// <summary>
	/// https://www.di-mgt.com.au/sha_testvectors.html
	/// </summary>
	[TestMethod]
	[DataRow(@"a", 1000000, @"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")]
	[DataRow(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e")]
	public void LargeMessageTest(string raw, int times, string expected)
	{
		TestUtils.LargeMessageTest(new DefaultSHA256Digest(), raw, times, expected);
		TestUtils.LargeMessageTest(new BcSHA256Digest(), raw, times, expected);
	}
}
