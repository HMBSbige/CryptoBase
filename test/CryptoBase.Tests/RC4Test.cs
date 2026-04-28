using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Tests;

public class RC4Test
{
	private static async Task Test_Internal(IStreamCrypto crypto, int originSize, string hex, string hex2)
	{
		await Assert.That(crypto.Name).IsEqualTo(@"RC4");

		byte[] h1 = hex.FromHex();

		byte[] h2 = hex2.FromHex();

		byte[] i = new byte[originSize];

		byte[] o = new byte[i.Length];

		crypto.Update(i, o);
		await Assert.That(h1.SequenceEqual(o)).IsTrue();

		crypto.Update(i, o);
		await Assert.That(h2.SequenceEqual(o)).IsTrue();

		crypto.Reset();

		crypto.Update(h1, o);
		await Assert.That(i.SequenceEqual(o)).IsTrue();

		crypto.Update(h2, o);
		await Assert.That(i.SequenceEqual(o)).IsTrue();

		crypto.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/rfc6229
	/// </summary>
	[Test]
	[Arguments(@"0102030405", 16, @"b2396305f03dc027ccc3524a0a1118a8", @"6982944f18fc82d589c403a47a0d0919")]
	[Arguments(@"01020304050607", 16, @"293f02d47f37c9b633f2af5285feb46b", @"e620f1390d19bd84e2e0fd752031afc1")]
	[Arguments(@"0102030405060708", 16, @"97ab8a1bf0afb96132f2f67258da15a8", @"8263efdb45c4a18684ef87e6b19e5b09")]
	[Arguments(@"0102030405060708090a", 8, @"ede3b04643e586cc", @"907dc21851709902")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f10", 8, @"9ac7cc9a609d1ef7", @"b2932899cde41b97")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f101112131415161718", 8, @"0595e57fe5f0bb3c", @"706edac8a4b2db11")]
	[Arguments(@"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 8, @"eaa6bd25880bf93d", @"3f5d1e4ca2611d91")]
	public async Task Test(string keyHex, int originSize, string hex, string hex2)
	{
		byte[] key = keyHex.FromHex();
		await Test_Internal(new BcRC4Crypto(key), originSize, hex, hex2);
		await Test_Internal(new RC4Crypto(key), originSize, hex, hex2);
	}
}
