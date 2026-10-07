namespace CryptoBase.Ciphers.Modes.Ccm;

internal static class CcmModeCore<TBlockCipher, TTag> where TBlockCipher : IBlockEncryptor<TBlockCipher> where TTag : struct, ICcmTag
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Encrypt(TBlockCipher cipher, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData)
	{
		CcmUtils.ValidateInput<TTag>(nonce, source, destination, tag);
		destination = destination.Slice(0, source.Length);

		if (BlockModeDispatch.TryEncryptCcm<TBlockCipher, TTag>(cipher, nonce, source, destination, tag, associatedData))
		{
			return;
		}

		EncryptBuffered(cipher, nonce, source, destination, tag, associatedData);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool TryDecrypt(TBlockCipher cipher, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData)
	{
		CcmUtils.ValidateInput<TTag>(nonce, source, destination, tag);
		destination = destination.Slice(0, source.Length);

		if (BlockModeDispatch.TryDecryptCcm<TBlockCipher, TTag>(cipher, nonce, source, tag, destination, associatedData, out bool authenticated))
		{
			return authenticated;
		}

		return TryDecryptBuffered(cipher, nonce, source, tag, destination, associatedData);
	}

	[SkipLocalsInit]
	private static void EncryptBuffered(TBlockCipher cipher, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData)
	{
		Span<byte> buffer = stackalloc byte[BufferedCcmBlockEncryptor<TBlockCipher>.BufferSize];

		try
		{
			CcmUtils.Encrypt<TTag, BufferedCcmBlockEncryptor<TBlockCipher>>(new BufferedCcmBlockEncryptor<TBlockCipher>(cipher, buffer), nonce, source, destination, tag, associatedData);
		}
		finally
		{
			buffer.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	private static bool TryDecryptBuffered(TBlockCipher cipher, scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData)
	{
		Span<byte> buffer = stackalloc byte[BufferedCcmBlockEncryptor<TBlockCipher>.BufferSize];

		try
		{
			return CcmUtils.TryDecrypt<TTag, BufferedCcmBlockEncryptor<TBlockCipher>>(new BufferedCcmBlockEncryptor<TBlockCipher>(cipher, buffer), nonce, source, tag, destination, associatedData);
		}
		finally
		{
			buffer.ZeroMemory();
		}
	}
}
