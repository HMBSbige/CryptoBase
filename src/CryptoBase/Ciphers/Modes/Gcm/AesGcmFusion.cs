using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static class AesGcmFusion
{
	internal static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => X86Base.X64.IsSupported && AesCipherX86.IsSupported && GHashX86.IsSupported || AdvSimd.Arm64.IsSupported && AesCipherArm.IsSupported && GHashArm.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldFuse(int length)
	{
		return IsSupported && length >= 64 && (!GHashX86.IsSupported512 || length < GHashX86.Vector512Threshold);
	}

	internal static void Encrypt(AesCipher aes, ref GHashKey hashKey, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(IsSupported && source.Length >= 64);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, GcmMode128<AesCipher>.NonceSize, GcmMode128<AesCipher>.TagSize);
		destination = destination.Slice(0, source.Length);
		Vector128<byte> counter = Gcm.Begin(nonce, out Vector128<byte> tagBuffer);
		GHash hash = GHash.Create(ref hashKey);

		try
		{
			// Consume AAD before writing ciphertext, including when the buffers overlap.
			hash.AppendPaddedSegmentsShort(associatedData);
			int processed = EncryptBlocks(aes, ref counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagBuffer);

			if (processed < source.Length)
			{
				GcmMode128<AesCipher>.Transform(aes, ref counter, source.Slice(processed), destination.Slice(processed));
			}

			Vector128<byte> lengthBlock = Gcm.CreateLengthBlock(associatedData.Length, source.Length);
			hash.AppendPaddedSegmentsShort(destination.Slice(processed), lengthBlock.AsReadOnlySpan());
			tagBuffer ^= hash.Accumulator;
			MemoryMarshal.Write(tag, in tagBuffer);
		}
		finally
		{
			hash.Dispose();
		}
	}

	private static int EncryptBlocks(AesCipher aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref GHashKey hashKey, ref Vector128<byte> accumulator, ref Vector128<byte> tagMask)
	{
		if (AesCipherX86.IsSupported)
		{
			return AesGcmX86.Encrypt(in aes.X86, ref counter, source, destination, ref hashKey, ref accumulator, ref tagMask);
		}

		return AesGcmArm.Encrypt(in aes.Arm, ref counter, source, destination, ref hashKey, ref accumulator, ref tagMask);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void XorStore8(ref byte input, ref byte output, nuint offset, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		v0 ^= Vector128.LoadUnsafe(ref input, offset);
		v0.StoreUnsafe(ref output, offset);
		v1 ^= Vector128.LoadUnsafe(ref input, offset + 16);
		v1.StoreUnsafe(ref output, offset + 16);
		v2 ^= Vector128.LoadUnsafe(ref input, offset + 32);
		v2.StoreUnsafe(ref output, offset + 32);
		v3 ^= Vector128.LoadUnsafe(ref input, offset + 48);
		v3.StoreUnsafe(ref output, offset + 48);
		v4 ^= Vector128.LoadUnsafe(ref input, offset + 64);
		v4.StoreUnsafe(ref output, offset + 64);
		v5 ^= Vector128.LoadUnsafe(ref input, offset + 80);
		v5.StoreUnsafe(ref output, offset + 80);
		v6 ^= Vector128.LoadUnsafe(ref input, offset + 96);
		v6.StoreUnsafe(ref output, offset + 96);
		v7 ^= Vector128.LoadUnsafe(ref input, offset + 112);
		v7.StoreUnsafe(ref output, offset + 112);
	}
}
