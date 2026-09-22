using CryptoBase.Ciphers.Blocks.Aes;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesBitsliceTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!AesCipherBitslice.IsSupported)
		{
			Skip.Test("SSE2 is not supported.");
		}
	}

	/// <summary>
	/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	/// </summary>
	[Test]
	[Arguments("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a")]
	[Arguments("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191")]
	[Arguments("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089")]
	public async Task StandardVectorEncryptsAndDecrypts(string keyHex, string ciphertextHex)
	{
		byte[] plain = Convert.FromHexString("00112233445566778899aabbccddeeff");
		byte[] cipher = Convert.FromHexString(ciphertextHex);
		using AesCipherBitslice crypto = AesCipherBitslice.Create(Convert.FromHexString(keyHex));

		byte[] source = new byte[8 * 16];
		byte[] expected = new byte[source.Length];

		for (int block = 0; block < 8; ++block)
		{
			plain.CopyTo(source, block * 16);
			cipher.CopyTo(expected, block * 16);
		}

		byte[] actual = new byte[source.Length];
		crypto.EncryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		crypto.DecryptBlocks(expected, actual);
		await Assert.That(actual).IsEquivalentTo(source, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task UnalignedBatchesAndInPlaceTransformsMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 65)] int blocks)
	{
		Random random = new(197 + keyLength);
		using BclAes reference = BclAes.Create();

		for (int iteration = 0; iteration < 3; ++iteration)
		{
			byte[] key = new byte[keyLength];
			random.NextBytes(key);
			reference.SetKey(key);
			using AesCipherBitslice crypto = AesCipherBitslice.Create(key);
			int sourceOffset = iteration * 7 + 1;
			int destinationOffset = 15 - iteration * 6;

			int length = blocks * 16;
			byte[] source = new byte[sourceOffset + length + 5];
			random.NextBytes(source);
			byte[] originalSource = source.ToArray();
			byte[] plain = source.AsSpan(sourceOffset, length).ToArray();
			byte[] encrypted = reference.EncryptEcb(plain, PaddingMode.None);
			byte[] decrypted = reference.DecryptEcb(plain, PaddingMode.None);
			byte[] actual = new byte[destinationOffset + length + 19];
			TestUtils.PrepareDestination(actual);

			crypto.EncryptBlocks(source.AsSpan(sourceOffset, length), actual.AsSpan(destinationOffset));
			await TestUtils.AssertOutput(actual, destinationOffset, encrypted);

			crypto.DecryptBlocks(actual.AsSpan(destinationOffset, length), actual.AsSpan(destinationOffset));
			await TestUtils.AssertOutput(actual, destinationOffset, plain);

			crypto.EncryptBlocks(actual.AsSpan(destinationOffset, length), actual.AsSpan(destinationOffset));
			await TestUtils.AssertOutput(actual, destinationOffset, encrypted);

			crypto.DecryptBlocks(source.AsSpan(sourceOffset, length), actual.AsSpan(destinationOffset));
			await TestUtils.AssertOutput(actual, destinationOffset, decrypted);
			await Assert.That(source).IsEquivalentTo(originalSource, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task AllByteValuesMatchBcl([Matrix(16, 24, 32)] int keyLength)
	{
		byte[] key = TestUtils.CreateDeterministicSource(keyLength);
		byte[] source = new byte[256 * 16];

		for (int value = 0; value < 256; ++value)
		{
			source.AsSpan(value * 16, 16).Fill((byte)value);
		}

		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		using AesCipherBitslice crypto = AesCipherBitslice.Create(key);
		byte[] actual = new byte[source.Length];
		crypto.EncryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.EncryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
		crypto.DecryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.DecryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
	}
}
