using CryptoBase.Ciphers.Blocks.Aes;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesVpaesTest
{
	[Before(Class)]
	public static void SkipWhenSsse3IsUnavailable()
	{
		if (!AesCipherVpaes.IsSupported)
		{
			Skip.Test("SSSE3 is not supported.");
		}
	}

	/// <summary>
	/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	/// </summary>
	[Test]
	[Arguments("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a")]
	[Arguments("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191")]
	[Arguments("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089")]
	[Arguments("80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8")]
	[Arguments("000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C")]
	[Arguments("0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E")]
	public async Task StandardVectorEncryptsAndDecrypts(string keyHex, string plaintextHex, string ciphertextHex)
	{
		byte[] plain = Convert.FromHexString(plaintextHex);
		byte[] cipher = Convert.FromHexString(ciphertextHex);

		using AesCipherVpaes crypto = AesCipherVpaes.Create(Convert.FromHexString(keyHex));

		byte[] actual = new byte[16];
		crypto.EncryptBlocks(plain, actual);
		await Assert.That(actual).IsEquivalentTo(cipher, CollectionOrdering.Matching);

		crypto.DecryptBlocks(cipher, actual);
		await Assert.That(actual).IsEquivalentTo(plain, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task BatchesMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(1, 2, 3, 4, 5, 6, 7, 8)] int blocks)
	{
		Random random = new(197 + keyLength * 16 + blocks);
		using BclAes reference = BclAes.Create();

		for (int iteration = 0; iteration < 8; ++iteration)
		{
			byte[] key = new byte[keyLength];
			random.NextBytes(key);
			reference.SetKey(key);
			using AesCipherVpaes crypto = AesCipherVpaes.Create(key);

			int length = blocks * 16;
			byte[] source = new byte[length];
			random.NextBytes(source);

			byte[] expected = reference.EncryptEcb(source, PaddingMode.None);
			byte[] actual = new byte[length];
			crypto.EncryptBlocks(source, actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

			crypto.DecryptBlocks(actual, actual);
			await Assert.That(actual).IsEquivalentTo(source, CollectionOrdering.Matching);

			expected = reference.DecryptEcb(source, PaddingMode.None);
			crypto.DecryptBlocks(source, actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task TransformWithMaskMatchesIndependentComposition([Matrix] bool decrypt, [Matrix] bool xorInput)
	{
		byte[] key = TestUtils.CreateDeterministicSource(32);
		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		using AesCipherVpaes crypto = AesCipherVpaes.Create(key);

		foreach (int blocks in new[] { 1, 2, 3, 4, 5 })
		{
			int length = blocks * 16;
			byte[] actual = TestUtils.CreateDeterministicSource(length);
			byte[] mask = TestUtils.CreateDeterministicSource(length + 1).AsSpan(1).ToArray();
			byte[] input = actual.ToArray();

			if (xorInput)
			{
				FastUtils.Xor(mask, input, input, input.Length);
			}

			byte[] expected = decrypt
				? reference.DecryptEcb(input, PaddingMode.None)
				: reference.EncryptEcb(input, PaddingMode.None);
			FastUtils.Xor(mask, expected, expected, expected.Length);

			crypto.TransformWithMask(actual, mask, actual, decrypt, xorInput);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	[Arguments(0)]
	[Arguments(15)]
	[Arguments(17)]
	[Arguments(31)]
	[Arguments(33)]
	public async Task InvalidKeyLengthsAreRejected(int length)
	{
		byte[] key = new byte[length];
		await Assert.That(() => AesCipherVpaes.Create(key)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
	}
}
