using CryptoBase.Ciphers.Blocks.Aes;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesVpaesTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!AesCipherVpaes.IsSupported)
		{
			Skip.Test("SSSE3 or ARM64 NEON is required.");
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
	public async Task UnalignedBatchesAndInPlaceTransformsMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 63, 64, 65, 257)] int blocks)
	{
		Random random = new(197 + keyLength * 16 + blocks);
		using BclAes reference = BclAes.Create();

		for (int iteration = 0; iteration < 8; ++iteration)
		{
			byte[] key = new byte[keyLength];
			random.NextBytes(key);
			reference.SetKey(key);
			using AesCipherVpaes crypto = AesCipherVpaes.Create(key);
			int sourceOffset = iteration * 7 % 15 + 1;
			int destinationOffset = 16 - sourceOffset;

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
		using AesCipherVpaes crypto = AesCipherVpaes.Create(key);
		byte[] actual = new byte[source.Length];
		crypto.EncryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.EncryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
		crypto.DecryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.DecryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task MaskedBatchesAndAliasesMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix] bool decrypt, [Matrix] bool xorInput)
	{
		Random random = new(197 + keyLength);
		byte[] key = new byte[keyLength];
		random.NextBytes(key);
		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		using AesCipherVpaes crypto = AesCipherVpaes.Create(key);

		foreach (int blocks in new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 63, 64, 65, 257 })
		{
			int length = blocks * 16;
			int sourceOffset = blocks % 15 + 1;
			int maskOffset = 16 - sourceOffset;
			int destinationOffset = blocks * 7 % 15 + 1;
			byte[] source = new byte[sourceOffset + length + 19];
			byte[] mask = new byte[maskOffset + length + 23];
			random.NextBytes(source);
			random.NextBytes(mask);
			byte[] originalSource = source.ToArray();
			byte[] originalMask = mask.ToArray();
			byte[] input = source.AsSpan(sourceOffset, length).ToArray();
			byte[] blockMask = mask.AsSpan(maskOffset, length).ToArray();
			byte[] expected = AesTestUtils.TransformReference(reference, input, blockMask, decrypt, xorInput);
			byte[] actual = new byte[destinationOffset + length + 17];
			TestUtils.PrepareDestination(actual);

			crypto.TransformWithMask(source.AsSpan(sourceOffset, length), mask.AsSpan(maskOffset, length), actual.AsSpan(destinationOffset), decrypt, xorInput);
			await TestUtils.AssertOutput(actual, destinationOffset, expected);
			await Assert.That(source).IsEquivalentTo(originalSource, CollectionOrdering.Matching);
			await Assert.That(mask).IsEquivalentTo(originalMask, CollectionOrdering.Matching);

			input.CopyTo(actual, destinationOffset);
			crypto.TransformWithMask(actual.AsSpan(destinationOffset, length), mask.AsSpan(maskOffset, length), actual.AsSpan(destinationOffset), decrypt, xorInput);
			await TestUtils.AssertOutput(actual, destinationOffset, expected);
			await Assert.That(mask).IsEquivalentTo(originalMask, CollectionOrdering.Matching);

			blockMask.CopyTo(actual, destinationOffset);
			crypto.TransformWithMask(source.AsSpan(sourceOffset, length), actual.AsSpan(destinationOffset, length), actual.AsSpan(destinationOffset), decrypt, xorInput);
			await TestUtils.AssertOutput(actual, destinationOffset, expected);
			await Assert.That(source).IsEquivalentTo(originalSource, CollectionOrdering.Matching);
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
