using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
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

			await AesTestUtils.AssertUnalignedAndInPlaceTransformsMatchBcl(reference, random, blocks, sourceOffset, destinationOffset, crypto.EncryptBlocks, crypto.DecryptBlocks);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task AllByteValuesMatchBcl([Matrix(16, 24, 32)] int keyLength)
	{
		byte[] key = TestUtils.CreateDeterministicSource(keyLength);
		using AesCipherVpaes crypto = AesCipherVpaes.Create(key);
		await AesTestUtils.AssertAllByteValuesMatchBcl(key, 16, crypto.EncryptBlocks, crypto.DecryptBlocks);
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
			await AesTestUtils.AssertMaskedTransformsMatchBcl(reference, random, blocks, decrypt, xorInput, (source, xorOperand, destination) => TransformWithMask(in crypto, source, xorOperand, destination, decrypt, xorInput));
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

	private static void TransformWithMask(in AesCipherVpaes crypto, ReadOnlySpan<byte> source, ReadOnlySpan<byte> xorOperand, Span<byte> destination, bool decrypt, bool xorInput)
	{
		if (xorInput)
		{
			AesInputOutputMaskPolicy policy = new(xorOperand);
			TransformWithPolicy(in crypto, ref policy, source, destination, decrypt);
		}
		else
		{
			AesOutputMaskPolicy policy = new(xorOperand);
			TransformWithPolicy(in crypto, ref policy, source, destination, decrypt);
		}
	}

	private static void TransformWithPolicy<TPolicy>(in AesCipherVpaes crypto, ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination, bool decrypt) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		if (decrypt)
		{
			crypto.TransformWithPolicy<TPolicy, Decryption>(ref policy, source, destination);
		}
		else
		{
			crypto.TransformWithPolicy<TPolicy, Encryption>(ref policy, source, destination);
		}
	}
}
