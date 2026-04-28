using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.DataFormatExtensions;
using CryptoBase.Digests.SHA256;
using System.Text;

namespace CryptoBase.Tests;

public class SHA256Test
{
	private static async Task SHA256DigestTest_Internal(IHash sha256, string str, string sha256Str)
	{
		await Assert.That(sha256.Name).IsEqualTo(@"SHA-256");
		await Assert.That(sha256.Length).IsEqualTo(32);
		await Assert.That(sha256.BlockSize).IsEqualTo(64);

		byte[] origin = Encoding.UTF8.GetBytes(str);

		byte[] hash = new byte[sha256.Length];

		sha256.UpdateFinal(origin, hash);
		sha256.UpdateFinal(origin, hash);

		await Assert.That(sha256Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha256.Update(origin);
		sha256.GetHash(hash);

		await Assert.That(sha256Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha256.Update(origin);
		sha256.Reset();

		sha256.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sha256.Update(origin.AsSpan().Slice(origin.Length / 2));
		sha256.GetHash(hash);

		await Assert.That(sha256Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha256.Update(origin.AsSpan().Slice(0, origin.Length / 2));
		sha256.UpdateFinal(origin.AsSpan().Slice(origin.Length / 2), hash);

		await Assert.That(sha256Str.SequenceEqual(hash.ToHex())).IsTrue();

		sha256.Dispose();
	}

	[Test]
	[Arguments(@"", @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")]
	[Arguments(@"abc", @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
	[Arguments(@"a", @"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")]
	[Arguments(@"abcdbcdecdefdefgefghfghighijhi", @"d578bbee0ee183a94170d4ff398cb29d06079a65101400771231f3fbb117c999")]
	[Arguments(@"jkijkljklmklmnlmnomnopnopq", @"fb29fa721adddc89b7b58e1c6a5577359f7e879c48672275617fe11ceb851d57")]
	[Arguments(@"01234567012345670123456701234567", @"dd0145169440e7e5c0347ab0c1b4f8c970e6ad3ff625a2edfc52878f384e7681")]
	public async Task SHA256DigestTest(string str, string sha256Str)
	{
		await SHA256DigestTest_Internal(new DefaultSHA256Digest(), str, sha256Str);
		await SHA256DigestTest_Internal(new BcSHA256Digest(), str, sha256Str);
	}

	/// <summary>
	/// https://www.di-mgt.com.au/sha_testvectors.html
	/// </summary>
	[Test]
	[Arguments(@"a", 1000000, @"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, @"50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e")]
	public async Task LargeMessageTest(string raw, int times, string expected)
	{
		await TestUtils.LargeMessageTest(new DefaultSHA256Digest(), raw, times, expected);
		await TestUtils.LargeMessageTest(new BcSHA256Digest(), raw, times, expected);
	}
}
