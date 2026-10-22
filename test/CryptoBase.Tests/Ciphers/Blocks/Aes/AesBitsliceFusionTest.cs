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

		await AesTestUtils.AssertMaskedTransformsMatchBcl(reference, random, blocks, decrypt, xorInput, (source, xorOperand, destination) => TransformWithMask(in crypto, source, xorOperand, destination, decrypt, xorInput));
	}

	private static void TransformWithMask(in AesCipherBitslice crypto, ReadOnlySpan<byte> source, ReadOnlySpan<byte> xorOperand, Span<byte> destination, bool decrypt, bool xorInput)
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

	private static void TransformWithPolicy<TPolicy>(in AesCipherBitslice crypto, ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination, bool decrypt) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		if (decrypt)
		{
			crypto.TransformWithPolicy<TPolicy, AesDecrypt>(ref policy, source, destination);
		}
		else
		{
			crypto.TransformWithPolicy<TPolicy, AesEncrypt>(ref policy, source, destination);
		}
	}
}
