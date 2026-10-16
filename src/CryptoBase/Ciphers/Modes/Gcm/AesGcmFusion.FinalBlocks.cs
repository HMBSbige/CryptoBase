using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmFusion
{
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void EncryptFinalBlocks(AesCipher aes, ref GHashKey hashKey, ref byte nonceStart, ref byte sourceStart, ref byte destinationStart, int length, ref byte tagStart, ref byte associatedDataStart, int associatedDataLength)
	{
		ReadOnlySpan<byte> nonce = MemoryMarshal.CreateReadOnlySpan(ref nonceStart, GcmMode128<AesCipher>.NonceSize);
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		Span<byte> tag = MemoryMarshal.CreateSpan(ref tagStart, GcmMode128<AesCipher>.TagSize);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);
		Vector128<byte> counter = Gcm.Begin(nonce, out Vector128<byte> tagBuffer);
		GHash hash = GHash.Create(ref hashKey);

		try
		{
			// Consume AAD before writing ciphertext, including when the buffers overlap.
			Vector128<byte> associatedDataBlock = HashAssociatedData(ref hash, associatedData);
			Vector128<byte> lengthBlock = Gcm.CreateLengthBlock(associatedData.Length, source.Length);

			if (AesCipherX86.IsSupported)
			{
				AesGcmX86.Transform<Encryption>(in aes.X86, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagBuffer, associatedDataBlock, lengthBlock);
			}
			else
			{
				AesGcmArm.Transform<Encryption>(in aes.Arm, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagBuffer, associatedDataBlock, lengthBlock);
			}

			tagBuffer ^= hash.Accumulator;
			MemoryMarshal.Write(tag, in tagBuffer);
		}
		finally
		{
			hash.Dispose();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static bool DecryptFinalBlocks(AesCipher aes, ref GHashKey hashKey, ref byte nonceStart, ref byte sourceStart, ref byte destinationStart, int length, ref byte tagStart, ref byte associatedDataStart, int associatedDataLength)
	{
		ReadOnlySpan<byte> nonce = MemoryMarshal.CreateReadOnlySpan(ref nonceStart, GcmMode128<AesCipher>.NonceSize);
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);
		Vector128<byte> counter = Gcm.Begin(nonce, out Vector128<byte> tagMask);
		GHash hash = GHash.Create(ref hashKey);

		try
		{
			// Consume AAD before writing plaintext, including when the buffers overlap.
			Vector128<byte> associatedDataBlock = HashAssociatedData(ref hash, associatedData);
			Vector128<byte> lengthBlock = Gcm.CreateLengthBlock(associatedData.Length, source.Length);

			if (AesCipherX86.IsSupported)
			{
				AesGcmX86.Transform<Decryption>(in aes.X86, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagMask, associatedDataBlock, lengthBlock);
			}
			else
			{
				AesGcmArm.Transform<Decryption>(in aes.Arm, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagMask, associatedDataBlock, lengthBlock);
			}

			if (FixedTime.Equals16(tagMask ^ hash.Accumulator, Vector128.LoadUnsafe(ref tagStart)))
			{
				return true;
			}

			destination.ZeroMemory();
			return false;
		}
		finally
		{
			hash.Dispose();
		}
	}

	// Leaves AAD of at most one block for the kernel to hash; the GHASH state is then hash ^ (block * H).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashAssociatedData(ref GHash hash, ReadOnlySpan<byte> associatedData)
	{
		if (associatedData.Length <= GHash.BlockSizeInBytes)
		{
			return associatedData.IsEmpty ? Vector128<byte>.Zero : Vector128.LoadPartialUnsafe(ref MemoryMarshal.GetReference(associatedData), 0, associatedData.Length);
		}

		hash.AppendPaddedSegmentsShort(associatedData);
		return Vector128<byte>.Zero;
	}
}
