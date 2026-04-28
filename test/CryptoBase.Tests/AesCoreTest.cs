using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class AesCoreTest
{
	/// <summary>
	/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	/// </summary>
	[Test]
	[Arguments(@"000102030405060708090a0b0c0d0e0f", @"00112233445566778899aabbccddeeff", @"69c4e0d86a7b0430d8cdb78070b4c55a")]
	[Arguments(@"000102030405060708090a0b0c0d0e0f1011121314151617", @"00112233445566778899aabbccddeeff", @"dda97ca4864cdfe06eaf70a0ec0d7191")]
	[Arguments(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"00112233445566778899aabbccddeeff", @"8ea2b7ca516745bfeafc49904b496089")]
	[Arguments(@"80000000000000000000000000000000", @"00000000000000000000000000000000", @"0EDD33D3C621E546455BD8BA1418BEC8")]
	[Arguments(@"000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"6CD02513E8D4DC986B4AFE087A60BD0C")]
	[Arguments(@"0000000000000000000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"DDC6BF790C15760D8D9AEB6F9A75FD4E")]
	public async Task Test(string keyHex, string hex1, string hex2)
	{
		byte[] key = keyHex.FromHex();
		byte[] plain = hex1.FromHex();
		byte[] cipher = hex2.FromHex();

		await TestUtils.TestBlock16<BcAesCipher>(key, plain, cipher);
		await TestUtils.TestBlock16<AesCipher>(key, plain, cipher);
	}

	[Test]
	[Arguments(16)]
	[Arguments(24)]
	[Arguments(32)]
	public async Task TestN(int keyLength)
	{
		byte[] key = RandomNumberGenerator.GetBytes(keyLength);

		await TestUtils.TestNBlock16<BcAesCipher>(key);
		await TestUtils.TestNBlock16<AesCipher>(key);
	}
}
