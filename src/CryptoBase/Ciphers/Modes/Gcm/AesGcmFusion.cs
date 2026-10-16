using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmFusion
{
	internal static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => X86Base.X64.IsSupported && AesCipherX86.IsSupported && GHashX86.IsSupported || AdvSimd.Arm64.IsSupported && AesCipherArm.IsSupported && GHashArm.IsSupported;
	}

	internal static bool TryDecrypt(AesCipher aes, ref GHashKey hashKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(IsSupported);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, GcmMode128<AesCipher>.NonceSize, GcmMode128<AesCipher>.TagSize);
		return DecryptFinalBlocks(aes, ref hashKey, ref MemoryMarshal.GetReference(nonce), ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length, ref MemoryMarshal.GetReference(tag), ref MemoryMarshal.GetReference(associatedData), associatedData.Length);
	}

	internal static void Encrypt(AesCipher aes, ref GHashKey hashKey, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData)
	{
		Debug.Assert(IsSupported);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, GcmMode128<AesCipher>.NonceSize, GcmMode128<AesCipher>.TagSize);
		EncryptFinalBlocks(aes, ref hashKey, ref MemoryMarshal.GetReference(nonce), ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length, ref MemoryMarshal.GetReference(tag), ref MemoryMarshal.GetReference(associatedData), associatedData.Length);
	}
}
