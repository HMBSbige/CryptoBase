using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoBase.Tests;

[TestClass]
public class XChaCha20Poly1305Test
{
	private static void Test(IAEADCrypto crypto, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		Assert.AreEqual(@"XChaCha20-Poly1305", crypto.Name);

		ReadOnlySpan<byte> nonce = nonceHex.FromHex();
		ReadOnlySpan<byte> associatedData = associatedDataHex.FromHex();
		ReadOnlySpan<byte> tag = tagHex.FromHex();
		ReadOnlySpan<byte> plain = plainHex.FromHex();
		ReadOnlySpan<byte> cipher = cipherHex.FromHex();
		Span<byte> o1 = stackalloc byte[plain.Length];
		Span<byte> o2 = stackalloc byte[16];

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.IsTrue(o1.SequenceEqual(cipher));
		Assert.IsTrue(o2.SequenceEqual(tag));

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.IsTrue(o1.SequenceEqual(cipher));
		Assert.IsTrue(o2.SequenceEqual(tag));

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.IsTrue(o1.SequenceEqual(plain));

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.IsTrue(o1.SequenceEqual(plain));

		crypto.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03
	/// </summary>
	[TestMethod]
	[DataRow(@"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F", @"404142434445464748494a4b4c4d4e4f5051525354555657", @"50515253C0C1C2C3C4C5C6C7",
		@"C0875924C1C7987947DEAFD8780ACF49",
		@"4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E",
		@"BD6D179D3E83D43B9576579493C0E939572A1700252BFACCBED2902C21396CBB731C7F1B0B4AA6440BF3A82F4EDA7E39AE64C6708C54C216CB96B72E1213B4522F8C9BA40DB5D945B11B69B982C1BB9E3F3FAC2BC369488F76B2383565D3FFF921F9664C97637DA9768812F615C68B13B52E")]
	public void Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		var key = keyHex.FromHex();
		Test(new BcXChaCha20Poly1305Crypto(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
		Test(AEADCryptoCreate.XChaCha20Poly1305(key), nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}
}
