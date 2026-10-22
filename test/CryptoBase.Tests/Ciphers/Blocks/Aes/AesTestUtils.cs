using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

internal static class AesTestUtils
{
	public delegate void BlockTransform(ReadOnlySpan<byte> source, Span<byte> destination);

	public delegate void MaskedTransform(ReadOnlySpan<byte> source, ReadOnlySpan<byte> xorOperand, Span<byte> destination);

	public static async Task AssertUnalignedAndInPlaceTransformsMatchBcl(BclAes reference, Random random, int blocks, int sourceOffset, int destinationOffset, BlockTransform encrypt, BlockTransform decrypt)
	{
		int length = blocks * 16;
		byte[] source = new byte[sourceOffset + length + 5];
		random.NextBytes(source);
		byte[] originalSource = source.ToArray();
		byte[] plain = source.AsSpan(sourceOffset, length).ToArray();
		byte[] encrypted = reference.EncryptEcb(plain, PaddingMode.None);
		byte[] decrypted = reference.DecryptEcb(plain, PaddingMode.None);
		byte[] actual = TestUtils.CreateGuardedBuffer(destinationOffset, length, 19);

		encrypt(source.AsSpan(sourceOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, encrypted);

		decrypt(actual.AsSpan(destinationOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, plain);

		encrypt(actual.AsSpan(destinationOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, encrypted);

		decrypt(source.AsSpan(sourceOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, decrypted);
		await Assert.That(source).IsEquivalentTo(originalSource, CollectionOrdering.Matching);
	}

	public static async Task AssertAllByteValuesMatchBcl(byte[] key, int runLength, BlockTransform encrypt, BlockTransform decrypt)
	{
		byte[] source = new byte[256 * runLength];

		for (int value = 0; value < 256; ++value)
		{
			source.AsSpan(value * runLength, runLength).Fill((byte)value);
		}

		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		byte[] actual = new byte[source.Length];
		encrypt(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.EncryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
		decrypt(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.DecryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
	}

	public static async Task AssertMaskedTransformsMatchBcl(BclAes reference, Random random, int blocks, bool decrypt, bool xorInput, MaskedTransform transform)
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
		byte[] expected = TransformReference(reference, input, blockMask, decrypt, xorInput);
		byte[] actual = TestUtils.CreateGuardedBuffer(destinationOffset, length, 17);

		transform(source.AsSpan(sourceOffset, length), mask.AsSpan(maskOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, expected);
		await Assert.That(source).IsEquivalentTo(originalSource, CollectionOrdering.Matching);
		await Assert.That(mask).IsEquivalentTo(originalMask, CollectionOrdering.Matching);

		input.CopyTo(actual, destinationOffset);
		transform(actual.AsSpan(destinationOffset, length), mask.AsSpan(maskOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, expected);
		await Assert.That(mask).IsEquivalentTo(originalMask, CollectionOrdering.Matching);

		blockMask.CopyTo(actual, destinationOffset);
		transform(source.AsSpan(sourceOffset, length), actual.AsSpan(destinationOffset, length), actual.AsSpan(destinationOffset));
		await TestUtils.AssertOutput(actual, destinationOffset, expected);
		await Assert.That(source).IsEquivalentTo(originalSource, CollectionOrdering.Matching);
	}

	private static byte[] TransformReference(BclAes reference, byte[] source, byte[] mask, bool decrypt, bool xorInput)
	{
		byte[] input = xorInput ? source.ToArray() : source;

		if (xorInput)
		{
			for (int i = 0; i < input.Length; ++i)
			{
				input[i] ^= mask[i];
			}
		}

		byte[] output = decrypt
			? reference.DecryptEcb(input, PaddingMode.None)
			: reference.EncryptEcb(input, PaddingMode.None);

		for (int i = 0; i < output.Length; ++i)
		{
			output[i] ^= mask[i];
		}

		return output;
	}
}
