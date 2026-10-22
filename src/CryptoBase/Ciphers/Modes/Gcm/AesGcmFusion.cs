using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static class AesGcmFusion
{
	internal static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => X86Base.X64.IsSupported && AesCipherX86.IsSupported && GHashX86.IsSupported || AdvSimd.Arm64.IsSupported && AesCipherArm.IsSupported && GHashArm.IsSupported;
	}

	internal static bool TryDecrypt(AesCipher aes, ref GHashKey hashKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(IsSupported);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, GcmMode<AesCipher>.NonceSize, GcmMode<AesCipher>.TagSize);
		return Transform<Decryption>(aes, ref hashKey, ref MemoryMarshal.GetReference(nonce), ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length, ref MemoryMarshal.GetReference(tag), ref MemoryMarshal.GetReference(associatedData), associatedData.Length);
	}

	internal static void Encrypt(AesCipher aes, ref GHashKey hashKey, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(IsSupported);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, GcmMode<AesCipher>.NonceSize, GcmMode<AesCipher>.TagSize);
		Transform<Encryption>(aes, ref hashKey, ref MemoryMarshal.GetReference(nonce), ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length, ref MemoryMarshal.GetReference(tag), ref MemoryMarshal.GetReference(associatedData), associatedData.Length);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static bool Transform<TDirection>(AesCipher aes, ref GHashKey hashKey, ref byte nonceStart, ref byte sourceStart, ref byte destinationStart, int length, ref byte tagStart, ref byte associatedDataStart, int associatedDataLength) where TDirection : struct, IBlockDirection
	{
		ReadOnlySpan<byte> nonce = MemoryMarshal.CreateReadOnlySpan(ref nonceStart, GcmMode<AesCipher>.NonceSize);
		ReadOnlySpan<byte> source = MemoryMarshal.CreateReadOnlySpan(ref sourceStart, length);
		Span<byte> destination = MemoryMarshal.CreateSpan(ref destinationStart, length);
		ReadOnlySpan<byte> associatedData = MemoryMarshal.CreateReadOnlySpan(ref associatedDataStart, associatedDataLength);
		Vector128<byte> counter = Gcm.Begin(nonce, out Vector128<byte> tagMask);
		GHash hash = GHash.Create(ref hashKey);

		try
		{
			// Consume AAD before writing the output, including when the buffers overlap.
			Vector128<byte> associatedDataBlock = HashAssociatedData(ref hash, associatedData);
			Vector128<byte> lengthBlock = Gcm.CreateLengthBlock(associatedData.Length, source.Length);

			if (AesCipherX86.IsSupported)
			{
				AesGcmX86.Transform<TDirection>(in aes.X86, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagMask, associatedDataBlock, lengthBlock);
			}
			else
			{
				AesGcmArm.Transform<TDirection>(in aes.Arm, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagMask, associatedDataBlock, lengthBlock);
			}

			if (!TDirection.IsDecrypt)
			{
				(tagMask ^ hash.Accumulator).StoreUnsafe(ref tagStart);
				return true;
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

		hash.AppendPaddedSegmentShort(associatedData);
		return Vector128<byte>.Zero;
	}
}
