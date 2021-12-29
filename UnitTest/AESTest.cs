using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest;

[TestClass]
public class AESTest
{
	private static void Test(IBlockCrypto crypto, string hex1, string hex2)
	{
		Assert.AreEqual(@"AES", crypto.Name);
		Assert.AreEqual(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> o1 = stackalloc byte[crypto.BlockSize];

		crypto.Encrypt(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Encrypt(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Decrypt(h2, o1);
		Assert.IsTrue(o1.SequenceEqual(h1));

		crypto.Decrypt(h2, o1);
		Assert.IsTrue(o1.SequenceEqual(h1));

		crypto.Dispose();
	}

	private static void Test4(IBlockCrypto crypto, string hex1, string hex2)
	{
		Assert.AreEqual(@"AES", crypto.Name);
		Assert.AreEqual(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> o1 = stackalloc byte[crypto.BlockSize * 4];

		crypto.Encrypt4(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Encrypt4(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Dispose();
	}

	/// <summary>
	/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	/// </summary>
	[TestMethod]
	[DataRow(@"000102030405060708090a0b0c0d0e0f", @"00112233445566778899aabbccddeeff", @"69c4e0d86a7b0430d8cdb78070b4c55a")]
	[DataRow(@"000102030405060708090a0b0c0d0e0f1011121314151617", @"00112233445566778899aabbccddeeff", @"dda97ca4864cdfe06eaf70a0ec0d7191")]
	[DataRow(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"00112233445566778899aabbccddeeff", @"8ea2b7ca516745bfeafc49904b496089")]
	[DataRow(@"80000000000000000000000000000000", @"00000000000000000000000000000000", @"0EDD33D3C621E546455BD8BA1418BEC8")]
	[DataRow(@"000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"6CD02513E8D4DC986B4AFE087A60BD0C")]
	[DataRow(@"0000000000000000000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"DDC6BF790C15760D8D9AEB6F9A75FD4E")]
	public void Test(string keyHex, string hex1, string hex2)
	{
		var key = keyHex.FromHex();
		Test(new BcAESCrypto(default, key), hex1, hex2);
		Test(new AESCryptoSF(key), hex1, hex2);
		Test(AESUtils.CreateECB(key), hex1, hex2);
		Test(new AESECBCrypto(key), hex1, hex2);
	}

	[TestMethod]
	[DataRow(@"000102030405060708090a0b0c0d0e0f", @"000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff80000000000000000000000000000000", @"0a940bb5416ef045f1c39458c653ea5a69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a4399572cd6ea5341b8d35876a7098af7")]
	public void Test4(string keyHex, string hex1, string hex2)
	{
		var key = keyHex.FromHex();
		Test4(new BcAESCrypto(default, key), hex1, hex2);
		Test4(new AESCryptoSF(key), hex1, hex2);
		Test4(AESUtils.CreateECB(key), hex1, hex2);
		Test4(new AESECBCrypto(key), hex1, hex2);
	}
}
