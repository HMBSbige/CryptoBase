using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes.Ctr;

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
				CtrBlocks<AesCipher, CtrIncrementer32>.Xor(aes, ref counter, source.Slice(processed), destination.Slice(processed));
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
}
