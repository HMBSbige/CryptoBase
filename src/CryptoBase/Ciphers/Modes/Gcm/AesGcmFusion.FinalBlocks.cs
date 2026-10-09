using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmFusion
{
	internal const int MaxFusedDecryptionLength = 255;

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
			Vector128<byte> associatedDataBlock = HashAssociatedData(ref hash, associatedData, source.Length < 64);
			Vector128<byte> lengthBlock = Gcm.CreateLengthBlock(associatedData.Length, source.Length);

			AesGcmX86.Encrypt(in aes.X86, counter, source, destination, ref hashKey, ref hash.Accumulator, ref tagBuffer, associatedDataBlock, lengthBlock);

			tagBuffer ^= hash.Accumulator;
			MemoryMarshal.Write(tag, in tagBuffer);
		}
		finally
		{
			hash.Dispose();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> HashAssociatedData(ref GHash hash, ReadOnlySpan<byte> associatedData, bool followedByRegisterBlocks)
	{
		if (followedByRegisterBlocks && associatedData.Length <= GHash.BlockSizeInBytes)
		{
			return associatedData.IsEmpty ? Vector128<byte>.Zero : Vector128.LoadPartialUnsafe(ref MemoryMarshal.GetReference(associatedData), 0, associatedData.Length);
		}

		hash.AppendPaddedSegmentsShort(associatedData);
		return Vector128<byte>.Zero;
	}
}
