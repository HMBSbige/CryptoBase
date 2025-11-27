using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class AesCoreTest
{
	private static void Test_Internal(IBlockCrypto crypto, string hex1, string hex2)
	{
		Assert.Equal(@"AES", crypto.Name);
		Assert.Equal(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> o1 = stackalloc byte[crypto.BlockSize + 1];

		crypto.Encrypt(h1, o1);
		Assert.Equal(h2, o1.Slice(0, crypto.BlockSize));

		crypto.Encrypt(h1, o1);
		Assert.Equal(h2, o1.Slice(0, crypto.BlockSize));

		crypto.Decrypt(h2, o1);
		Assert.Equal(h1, o1.Slice(0, crypto.BlockSize));

		crypto.Decrypt(h2, o1);
		Assert.Equal(h1, o1.Slice(0, crypto.BlockSize));

		crypto.Dispose();
	}

	/// <summary>
	/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	/// </summary>
	[Theory]
	[InlineData(@"000102030405060708090a0b0c0d0e0f", @"00112233445566778899aabbccddeeff", @"69c4e0d86a7b0430d8cdb78070b4c55a")]
	[InlineData(@"000102030405060708090a0b0c0d0e0f1011121314151617", @"00112233445566778899aabbccddeeff", @"dda97ca4864cdfe06eaf70a0ec0d7191")]
	[InlineData(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"00112233445566778899aabbccddeeff", @"8ea2b7ca516745bfeafc49904b496089")]
	[InlineData(@"80000000000000000000000000000000", @"00000000000000000000000000000000", @"0EDD33D3C621E546455BD8BA1418BEC8")]
	[InlineData(@"000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"6CD02513E8D4DC986B4AFE087A60BD0C")]
	[InlineData(@"0000000000000000000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"DDC6BF790C15760D8D9AEB6F9A75FD4E")]
	public void Test(string keyHex, string hex1, string hex2)
	{
		ReadOnlySpan<byte> key = keyHex.FromHex();
		ReadOnlySpan<byte> plain = hex1.FromHex();
		ReadOnlySpan<byte> cipher = hex2.FromHex();

		Test_Internal(new BcAesCrypto(key), hex1, hex2);
		Test_Internal(AesCrypto.CreateCore(key), hex1, hex2);
		Test_Internal(new DefaultAesCrypto(key), hex1, hex2);

		TestUtils.TestBlock16<AesCryptoNg>(key, plain, cipher);
	}

	[Theory]
	[InlineData(16)]
	[InlineData(24)]
	[InlineData(32)]
	public void TestN(int keyLength)
	{
		ReadOnlySpan<byte> key = RandomNumberGenerator.GetBytes(keyLength);

		TestUtils.TestNBlock16(new BcAesCrypto(key));
		TestUtils.TestNBlock16(AesCrypto.CreateCore(key));
		TestUtils.TestNBlock16(new DefaultAesCrypto(key));
	}
}
