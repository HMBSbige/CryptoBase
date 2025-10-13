using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Tests;

public class RC4Test
{
	private static void Test_Internal(IStreamCrypto crypto, int originSize, string hex, string hex2)
	{
		Assert.Equal(@"RC4", crypto.Name);

		Span<byte> h1 = hex.FromHex();
		Span<byte> h2 = hex2.FromHex();

		Span<byte> i = new byte[originSize];
		Span<byte> o = stackalloc byte[i.Length];

		crypto.Update(i, o);
		Assert.True(o.SequenceEqual(h1));

		crypto.Update(i, o);
		Assert.True(o.SequenceEqual(h2));

		crypto.Reset();

		crypto.Update(h1, o);
		Assert.True(o.SequenceEqual(i));

		crypto.Update(h2, o);
		Assert.True(o.SequenceEqual(i));

		crypto.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/rfc6229
	/// </summary>
	[Theory]
	[InlineData(@"0102030405", 16, @"b2396305f03dc027ccc3524a0a1118a8", @"6982944f18fc82d589c403a47a0d0919")]
	[InlineData(@"01020304050607", 16, @"293f02d47f37c9b633f2af5285feb46b", @"e620f1390d19bd84e2e0fd752031afc1")]
	[InlineData(@"0102030405060708", 16, @"97ab8a1bf0afb96132f2f67258da15a8", @"8263efdb45c4a18684ef87e6b19e5b09")]
	[InlineData(@"0102030405060708090a", 8, @"ede3b04643e586cc", @"907dc21851709902")]
	[InlineData(@"0102030405060708090a0b0c0d0e0f10", 8, @"9ac7cc9a609d1ef7", @"b2932899cde41b97")]
	[InlineData(@"0102030405060708090a0b0c0d0e0f101112131415161718", 8, @"0595e57fe5f0bb3c", @"706edac8a4b2db11")]
	[InlineData(@"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 8, @"eaa6bd25880bf93d", @"3f5d1e4ca2611d91")]
	public void Test(string keyHex, int originSize, string hex, string hex2)
	{
		byte[] key = keyHex.FromHex();
		Test_Internal(new BcRC4Crypto(key), originSize, hex, hex2);
		Test_Internal(StreamCryptoCreate.Rc4(key), originSize, hex, hex2);
	}
}
