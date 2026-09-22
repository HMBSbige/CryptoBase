using CryptoBase.Ciphers.Blocks.Aes;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesBitsliceFusionTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!AesCipherBitslice.IsSupported)
		{
			Skip.Test("SSE2 is not supported.");
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task MaskedBatchesAndAliasesMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 129)] int blocks, [Matrix] bool decrypt, [Matrix] bool xorInput)
	{
		Random random = new(197 + keyLength);
		byte[] key = new byte[keyLength];
		random.NextBytes(key);
		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		using AesCipherBitslice crypto = AesCipherBitslice.Create(key);

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
		byte[] actual = CreateGuardedBuffer(destinationOffset, length);

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

	private static byte[] CreateGuardedBuffer(int offset, int length)
	{
		byte[] buffer = new byte[offset + length + 17];
		TestUtils.PrepareDestination(buffer);
		return buffer;
	}
}
