using CryptoBase.Ciphers.Streams;
using CryptoBase.Macs.Poly1305;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Tests.Ciphers.Aead;

public class ChaCha20Poly1305FusionTest
{
	private static readonly int[] Lengths = [512, 513, 1023, 1024, 1025, 1536, 2047, 3072, 4111, 65537];

	[Test]
	public async Task Vector256KernelMatchesSeparatePasses()
	{
		if (!Vector256.IsHardwareAccelerated || !X86Base.X64.IsSupported || !Poly1305Avx2.IsSupported)
		{
			Skip.Test("The AVX2 ChaCha20-Poly1305 kernel is not supported here.");
		}

		await VerifyKernel<Poly1305Avx2>(512);
	}

	[Test]
	public async Task Vector512KernelMatchesSeparatePasses()
	{
		if (!Vector512.IsHardwareAccelerated || !Avx512F.IsSupported || !Poly1305Avx512.IsSupported)
		{
			Skip.Test("The AVX-512 ChaCha20-Poly1305 kernel is not supported here.");
		}

		await VerifyKernel<Poly1305Avx512>(1024);
	}

	private static async Task VerifyKernel<TState>(int minimumLength) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Random random = new(8439);

		foreach (int length in Lengths)
		{
			if (length < minimumLength)
			{
				continue;
			}

			byte[] key = new byte[32];
			byte[] nonce = new byte[12];
			byte[] poly1305Key = new byte[32];
			byte[] associatedData = new byte[13];
			byte[] plaintext = new byte[length];
			random.NextBytes(key);
			random.NextBytes(nonce);
			random.NextBytes(poly1305Key);
			random.NextBytes(associatedData);
			random.NextBytes(plaintext);

			byte[] expectedCiphertext = new byte[length];
			byte[] expectedTag = new byte[16];
			ComputeSeparately(key, nonce, poly1305Key, associatedData, plaintext, expectedCiphertext, expectedTag);

			byte[] ciphertext = new byte[length];
			byte[] tag = new byte[16];
			int processed = ComputeFused<TState>(key, nonce, poly1305Key, associatedData, plaintext, ciphertext, tag);

			await Assert.That(processed).IsGreaterThanOrEqualTo(length - minimumLength + 1);
			await Assert.That(ciphertext).IsEquivalentTo(expectedCiphertext, CollectionOrdering.Matching);
			await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		}
	}

	private static void ComputeSeparately(byte[] key, byte[] nonce, byte[] poly1305Key, byte[] associatedData, byte[] plaintext, byte[] ciphertext, byte[] tag)
	{
		using ChaCha20Cipher cipher = new(key, nonce);
		cipher.SetCounter(1);
		cipher.Xor(plaintext, ciphertext);

		Poly1305Software state = default;
		Poly1305Software.Initialize(ref state, poly1305Key);
		state.AppendPaddedSegment(associatedData);
		state.AppendMessage(ciphertext);
		state.WriteMac(tag);
	}

	private static int ComputeFused<TState>(byte[] key, byte[] nonce, byte[] poly1305Key, byte[] associatedData, byte[] plaintext, byte[] ciphertext, byte[] tag) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		using ChaCha20Cipher cipher = new(key, nonce);
		cipher.SetCounter(1);

		TState state = default;
		TState.Initialize(ref state, poly1305Key);
		// A non-zero accumulator checks the conversion into and out of the kernel.
		state.AppendPaddedSegment(associatedData);
		int processed = cipher.XorChunksAndAppendPoly1305(plaintext, ciphertext, ref state);
		cipher.Xor(plaintext.AsSpan(processed), ciphertext.AsSpan(processed));
		state.AppendMessage(ciphertext.AsSpan(processed));
		state.WriteMac(tag);
		return processed;
	}
}
