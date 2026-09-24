using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes.Gcm;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Aead;

public class AesGcmFusionTest
{
	public static IEnumerable<int> MessageLengths()
	{
		return [63, 64, 65, 127, 128, 129, 130, 131, 132, 136, 137, 191, 192, 193, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 1087, 1088, 1089, 1151, 1152, 1153, 2047, 2048, 2049, 4096, 4097, 65536, 65537];
	}

	[Test]
	[MatrixDataSource]
	public async Task UnalignedAndInPlaceMessagesMatchBclAcrossBatchBoundaries([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 17, 4097)] int associatedDataLength, [MatrixMethod<AesGcmFusionTest>(nameof(MessageLengths))] int length)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		using GcmMode128<AesCipher> cipher = GcmMode128<AesCipher>.Create(key);
		using AesGcm reference = new(key, GcmMode128<AesCipher>.TagSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] nonce = CreateDeterministicSource(GcmMode128<AesCipher>.NonceSize);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = new byte[length];
		byte[] expectedTag = new byte[GcmMode128<AesCipher>.TagSize];
		reference.Encrypt(nonce, plaintext, expected, expectedTag, associatedData);

		byte[] source = CreateGuardedBuffer(3, length);
		plaintext.CopyTo(source, 3);
		byte[] destination = CreateGuardedBuffer(5, length);
		byte[] tag = CreateGuardedBuffer(7, expectedTag.Length);
		cipher.Encrypt(nonce, source.AsSpan().Slice(3, length), destination.AsSpan().Slice(5), tag.AsSpan().Slice(7, expectedTag.Length), associatedData);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(tag, 7, expectedTag);
		await AssertOutput(source, 3, plaintext);

		PrepareDestination(destination);
		PrepareDestination(tag);
		plaintext.CopyTo(destination, 5);
		cipher.Encrypt(nonce, destination.AsSpan().Slice(5, length), destination.AsSpan().Slice(5), tag.AsSpan().Slice(7, expectedTag.Length), associatedData);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(tag, 7, expectedTag);

		// Exercise the internal entry point as well as public dispatch.
		if (length >= 64 && AesGcmFusion.IsSupported)
		{
			PrepareDestination(destination);
			PrepareDestination(tag);
			EncryptFused(key, nonce, source.AsSpan().Slice(3, length), destination.AsSpan().Slice(5), tag.AsSpan().Slice(7, expectedTag.Length), associatedData);
			await AssertOutput(destination, 5, expected);
			await AssertOutput(tag, 7, expectedTag);
			await AssertOutput(source, 3, plaintext);

			plaintext.CopyTo(destination, 5);
			PrepareDestination(tag);
			EncryptFused(key, nonce, destination.AsSpan().Slice(5, length), destination.AsSpan().Slice(5), tag.AsSpan().Slice(7, expectedTag.Length), associatedData);
			await AssertOutput(destination, 5, expected);
			await AssertOutput(tag, 7, expectedTag);
		}
	}

	public static IEnumerable<(int KeyLength, int Length, int AssociatedDataLength)> OverlappingAssociatedDataCases()
	{
		return [(16, 65, 4097), (24, 4097, 65), (32, 16385, 4097), (16, 513, 127), (24, 513, 128), (32, 513, 129)];
	}

	[Test]
	[MatrixDataSource]
	public async Task OverlappingAssociatedDataIsConsumedBeforeWritingCiphertext([MatrixMethod<AesGcmFusionTest>(nameof(OverlappingAssociatedDataCases))] (int KeyLength, int Length, int AssociatedDataLength) scenario)
	{
		(int keyLength, int length, int associatedDataLength) = scenario;
		const int destinationOffset = 7;
		const int associatedDataOffset = 3;
		byte[] key = CreateDeterministicSource(keyLength);
		using GcmMode128<AesCipher> cipher = GcmMode128<AesCipher>.Create(key);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] nonce = CreateDeterministicSource(GcmMode128<AesCipher>.NonceSize);
		byte[] expected = new byte[length];
		byte[] expectedTag = new byte[GcmMode128<AesCipher>.TagSize];
		using AesGcm reference = new(key, expectedTag.Length);
		reference.Encrypt(nonce, plaintext, expected, expectedTag, associatedData);

		byte[] buffer = CreateGuardedBuffer(destinationOffset, Math.Max(length, associatedDataLength));
		associatedData.CopyTo(buffer, associatedDataOffset);
		byte[] originalBuffer = buffer.ToArray();
		byte[] expectedBuffer = originalBuffer.ToArray();
		expected.CopyTo(expectedBuffer, destinationOffset);
		byte[] actualTag = new byte[expectedTag.Length];

		cipher.Encrypt(nonce, plaintext, buffer.AsSpan().Slice(destinationOffset), actualTag, buffer.AsSpan().Slice(associatedDataOffset, associatedDataLength));
		await Assert.That(buffer).IsEquivalentTo(expectedBuffer, CollectionOrdering.Matching);
		await Assert.That(actualTag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		if (AesGcmFusion.IsSupported)
		{
			originalBuffer.CopyTo(buffer, 0);
			PrepareDestination(actualTag);
			EncryptFused(key, nonce, plaintext, buffer.AsSpan().Slice(destinationOffset), actualTag, buffer.AsSpan().Slice(associatedDataOffset, associatedDataLength));
			await Assert.That(buffer).IsEquivalentTo(expectedBuffer, CollectionOrdering.Matching);
			await Assert.That(actualTag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		}
	}

	public static IEnumerable<(int BlocksPerBatch, int Length, string CounterHex)> KernelCases()
	{
		foreach (int blocksPerBatch in new[] { 4, 8 })
		{
			int batchSize = blocksPerBatch * 16;
			// Wrap inside the first batch, exactly after it, and inside the next batch.
			string[] counters = blocksPerBatch is 8
				? ["102132435465768798A9BACBFFFFFFFE", "102132435465768798A9BACBFFFFFFF8", "102132435465768798A9BACBFFFFFFF6"]
				: ["102132435465768798A9BACBFFFFFFFE", "102132435465768798A9BACBFFFFFFFC", "102132435465768798A9BACBFFFFFFFA"];

			foreach (string counterHex in counters)
			{
				foreach (int length in new[] { 0, batchSize - 1, batchSize, batchSize + 1, 2 * batchSize, 2 * batchSize + 1, 3 * batchSize + 1 })
				{
					yield return (blocksPerBatch, length, counterHex);
				}
			}
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task KernelWrapsOnlyTheLowCounterWordAndHashesProcessedBatches([Matrix(16, 24, 32)] int keyLength, [MatrixMethod<AesGcmFusionTest>(nameof(KernelCases))] (int BlocksPerBatch, int Length, string CounterHex) scenario)
	{
		if (!AesCipherArm.IsSupported && (!AesCipherX86.IsSupported || !GHashX86.IsSupported))
		{
			Skip.Test("AES-GCM hardware acceleration is not supported.");
		}

		(int blocksPerBatch, int length, string counterHex) = scenario;
		byte[] key = CreateDeterministicSource(keyLength);
		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		Vector128<byte> hashKey = MemoryMarshal.Read<Vector128<byte>>(reference.EncryptEcb(new byte[16], PaddingMode.None));
		Vector128<byte> initialHash = MemoryMarshal.Read<Vector128<byte>>(CreateDeterministicSource(16));

		int batchSize = blocksPerBatch * 16;
		int expectedProcessed = length / batchSize * batchSize;
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] initialCounter = Convert.FromHexString(counterHex);
		byte[] expectedCounter = initialCounter.ToArray();
		byte[] expected = EncryptCounterReference(reference, expectedCounter, plaintext.AsSpan().Slice(0, expectedProcessed));
		Vector128<byte> expectedHash = initialHash;
		GHashSoftware.AppendPaddedSegments(ref expectedHash, in hashKey, expected, default, default);
		byte[] expectedHashBytes = expectedHash.AsReadOnlySpan().ToArray();

		Vector128<byte> counter = MemoryMarshal.Read<Vector128<byte>>(initialCounter);
		Vector128<byte> accumulator = initialHash;
		byte[] source = CreateGuardedBuffer(3, length);
		plaintext.CopyTo(source, 3);
		byte[] destination = CreateGuardedBuffer(5, length);
		int processed = AesCipherArm.IsSupported
			? EncryptArmKernel(blocksPerBatch, key, ref counter, source.AsSpan().Slice(3, length), destination.AsSpan().Slice(5), ref accumulator, hashKey)
			: EncryptX86Kernel(blocksPerBatch, key, ref counter, source.AsSpan().Slice(3, length), destination.AsSpan().Slice(5), ref accumulator, hashKey);
		await Assert.That(processed).IsEqualTo(expectedProcessed);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(source, 3, plaintext);
		await Assert.That(counter.AsReadOnlySpan().ToArray()).IsEquivalentTo(expectedCounter, CollectionOrdering.Matching);
		await Assert.That(accumulator.AsReadOnlySpan().ToArray()).IsEquivalentTo(expectedHashBytes, CollectionOrdering.Matching);

		counter = MemoryMarshal.Read<Vector128<byte>>(initialCounter);
		accumulator = initialHash;
		plaintext.CopyTo(destination, 5);
		processed = AesCipherArm.IsSupported
			? EncryptArmKernel(blocksPerBatch, key, ref counter, destination.AsSpan().Slice(5, length), destination.AsSpan().Slice(5), ref accumulator, hashKey)
			: EncryptX86Kernel(blocksPerBatch, key, ref counter, destination.AsSpan().Slice(5, length), destination.AsSpan().Slice(5), ref accumulator, hashKey);
		byte[] expectedInPlace = plaintext.ToArray();
		expected.CopyTo(expectedInPlace, 0);
		await Assert.That(processed).IsEqualTo(expectedProcessed);
		await AssertOutput(destination, 5, expectedInPlace);
		await Assert.That(counter.AsReadOnlySpan().ToArray()).IsEquivalentTo(expectedCounter, CollectionOrdering.Matching);
		await Assert.That(accumulator.AsReadOnlySpan().ToArray()).IsEquivalentTo(expectedHashBytes, CollectionOrdering.Matching);
	}

	private static byte[] EncryptCounterReference(BclAes reference, byte[] counter, ReadOnlySpan<byte> source)
	{
		byte[] ciphertext = new byte[source.Length];
		Span<byte> mask = stackalloc byte[16];

		for (int offset = 0; offset < source.Length; offset += 16)
		{
			reference.EncryptEcb(counter, mask, PaddingMode.None);

			for (int i = 0; i < mask.Length; ++i)
			{
				ciphertext[offset + i] = (byte)(source[offset + i] ^ mask[i]);
			}

			for (int i = 15; i >= 12; --i)
			{
				counter[i] = unchecked((byte)(counter[i] + 1));

				if (counter[i] is not 0)
				{
					break;
				}
			}
		}

		return ciphertext;
	}

	private static void EncryptFused(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		using AesCipher cipher = AesCipher.Create(key);
		Vector128<byte> h = default;
		cipher.EncryptBlock(h.AsReadOnlySpan(), h.AsSpan());
		GHashKey hashKey = GHashKey.Create(h.AsReadOnlySpan());
		h.ZeroMemory();

		try
		{
			AesGcmFusion.Encrypt(cipher, ref hashKey, nonce, source, destination, tag, associatedData);
		}
		finally
		{
			hashKey.Dispose();
		}
	}

	private static int EncryptArmKernel(int blocksPerBatch, byte[] key, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, Vector128<byte> hashKey)
	{
		AesCipherArm cipher = AesCipherArm.Create(key);
		Vector128<byte> tagMask = default;
		GHashArmPrecomputedKey powers = new(AdvSimd.Arm64.ReverseElementBits(hashKey));
		accumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);

		try
		{
			int processed = blocksPerBatch is 8
				? AesGcmArm.Encrypt8(in cipher, ref counter, source, destination, ref accumulator, in powers, ref tagMask)
				: AesGcmArm.Encrypt4(in cipher, ref counter, source, destination, ref accumulator, in powers);
			accumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
			return processed;
		}
		finally
		{
			powers.ZeroMemory();
			cipher.Dispose();
		}
	}

	private static int EncryptX86Kernel(int blocksPerBatch, byte[] key, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, Vector128<byte> hashKey)
	{
		AesCipherX86 cipher = AesCipherX86.Create(key);
		GHashVector128PrecomputedKey powers = new(hashKey.ReverseEndianness128());
		accumulator = accumulator.ReverseEndianness128();

		try
		{
			int processed = blocksPerBatch is 8
				? AesGcmX86.Encrypt8(in cipher, ref counter, source, destination, ref accumulator, in powers)
				: AesGcmX86.Encrypt4(in cipher, ref counter, source, destination, ref accumulator, in powers);
			accumulator = accumulator.ReverseEndianness128();
			return processed;
		}
		finally
		{
			powers.ZeroMemory();
			cipher.Dispose();
		}
	}
}
