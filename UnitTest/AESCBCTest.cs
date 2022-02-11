using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest;

[TestClass]
public class AESCBCTest
{
	private static void Test(IBlockCrypto crypto, string hex1, string hex2)
	{
		Assert.AreEqual(@"AES-CBC", crypto.Name);
		Assert.AreEqual(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> o1 = stackalloc byte[crypto.BlockSize];

		crypto.Encrypt(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Reset();

		crypto.Encrypt(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Reset();

		crypto.Decrypt(h2, o1);
		Assert.IsTrue(o1.SequenceEqual(h1));

		crypto.Reset();

		crypto.Decrypt(h2, o1);
		Assert.IsTrue(o1.SequenceEqual(h1));

		crypto.Dispose();
	}

	/// <summary>
	/// https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CBC','Hex','Hex','')
	/// </summary>
	[TestMethod]
	[DataRow(@"000102030405060708090a0b0c0d0e0f", @"fe3577795961e1fbbbb82528c74d2e99",
		@"00112233445566778899aabbccddeeff", @"976b0f03fb159e3f82298814b4b7173c")]
	[DataRow(@"000102030405060708090a0b0c0d0e0f1011121314151617", @"fe3577795961e1fbbbb82528c74d2e99",
		@"00112233445566778899aabbccddeeff", @"e26d6f1ca88b566eddf49b1ef372db6e")]
	[DataRow(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"fe3577795961e1fbbbb82528c74d2e99",
		@"00112233445566778899aabbccddeeff", @"93010f33350c4e774778bea533e18cf2")]
	public void Test(string keyHex, string ivHex, string hex1, string hex2)
	{
		var key = keyHex.FromHex();
		var iv = ivHex.FromHex();
		Test(new AESCBCCrypto(key, iv), hex1, hex2);
		Test(new CBCBlockMode(AESUtils.CreateECB(key), iv), hex1, hex2);
	}
}
