using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes.Ctr;
using CryptoBase.Ciphers.Modes.Gcm;
using CryptoBase.Ciphers.Modes.Xts;

namespace CryptoBase.Ciphers.Modes;

internal static class BlockModeDispatch
{
	private const int BlockSize = 16;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int XorCtr<TCipher, TIncrementer>(TCipher cipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination) where TCipher : IBlockEncryptor<TCipher> where TIncrementer : struct, ICtrIncrementer
	{
		if (cipher is SM4Cipher sm4)
		{
			return sm4.TransformBatches<SM4CtrPolicy<TIncrementer>>(ref counter, source, destination);
		}

		if (source.Length >= 2 * BlockSize)
		{
			int length = source.Length & -BlockSize;

			if (TryTransformAes<TCipher, AesCtrPolicy<TIncrementer>, AesEncrypt>(cipher, ref counter, source.Slice(0, length), destination))
			{
				return length;
			}
		}

		return 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryEncryptXor<TCipher>(TCipher cipher, ReadOnlySpan<byte> counters, ReadOnlySpan<byte> data, Span<byte> destination) where TCipher : IBlockEncryptor<TCipher>
	{
		// No IsAesVectorSupported check: AesCipher also handles this on VPAES and bitslice.
		return cipher is AesCipher aes && aes.TryEncryptXor(counters, data, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryTransformXts<TCipher, TDirection>(TCipher cipher, ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination) where TCipher : IBlockCipher<TCipher> where TDirection : struct, IBlockDirection
	{
		return TDirection.IsDecrypt
			? TryTransformAes<TCipher, AesXtsPolicy, AesDecrypt>(cipher, ref tweak, source, destination)
			: TryTransformAes<TCipher, AesXtsPolicy, AesEncrypt>(cipher, ref tweak, source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryTransformXex<TCipher, TDirection>(TCipher cipher, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tweaks, Span<byte> destination) where TCipher : IBlockCipher<TCipher> where TDirection : struct, IBlockDirection
	{
		// No IsAesVectorSupported check: AesCipher also handles this on VPAES and bitslice.
		return cipher is AesCipher aes && (TDirection.IsDecrypt ? aes.TryDecryptXex(source, tweaks, destination) : aes.TryEncryptXex(source, tweaks, destination));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> TransformBlock<TCipher, TDirection>(TCipher cipher, Vector128<byte> value) where TCipher : IBlockCipher<TCipher> where TDirection : struct, IBlockDirection
	{
		if (IsAesVectorSupported && cipher is AesCipher aes)
		{
			if (AesCipherX86.IsSupported)
			{
				return TDirection.IsDecrypt ? aes.X86.Decrypt(value) : aes.X86.Encrypt(value);
			}

			return TDirection.IsDecrypt ? aes.Arm.Decrypt(value) : aes.Arm.Encrypt(value);
		}

		if (TDirection.IsDecrypt)
		{
			cipher.DecryptBlock(value.AsReadOnlySpan(), value.AsSpan());
		}
		else
		{
			cipher.EncryptBlock(value.AsReadOnlySpan(), value.AsSpan());
		}

		return value;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryEncryptGcm<TCipher>(TCipher cipher, ref GHashKey hashKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData) where TCipher : IBlockEncryptor<TCipher>
	{
		if (AesGcmFusion.ShouldFuse(source.Length) && cipher is AesCipher aes)
		{
			AesGcmFusion.Encrypt(aes, ref hashKey, nonce, source, destination, tag, associatedData);
			return true;
		}

		return false;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldBatchGcmTagMask<TCipher>(TCipher cipher) where TCipher : IBlockEncryptor<TCipher>
	{
		// SM4 batches E(J0) with data counters to avoid its separate single-block encryption latency.
		return cipher is SM4Cipher;
	}

	private static bool IsAesVectorSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => AesCipherX86.IsSupported || AesCipherArm.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryTransformAes<TCipher, TPolicy, TOperation>(TCipher cipher, ref Vector128<byte> state, ReadOnlySpan<byte> source, Span<byte> destination) where TCipher : IBlockEncryptor<TCipher> where TPolicy : struct, IAesModePolicy where TOperation : struct, IAesOperation
	{
		return IsAesVectorSupported && cipher is AesCipher aes && aes.TryTransform<TPolicy, TOperation>(ref state, source, destination);
	}
}
