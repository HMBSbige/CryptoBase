namespace CryptoBase.SymmetricCryptos.AeadCryptos;

/// <summary>
/// Provides AES-GCM authenticated encryption using <see cref="AesGcm"/> with 12-byte nonces and 16-byte tags.
/// </summary>
/// <param name="key">The 16-, 24-, or 32-byte AES key.</param>
public sealed class DefaultAesGcmCrypto(ReadOnlySpan<byte> key) : IAeadCrypto
{
	/// <inheritdoc />
	public string Name => @"AES-GCM";

	/// <inheritdoc />
	public int NonceSizeInBytes => NonceSize;

	/// <inheritdoc />
	public int TagSizeInBytes => TagSize;

	private readonly AesGcm _internalCrypto = new(key, TagSize);

	/// <summary>
	/// The required nonce size, in bytes.
	/// </summary>
	public const int NonceSize = 12;

	/// <summary>
	/// The authentication tag size, in bytes.
	/// </summary>
	public const int TagSize = 16;

	/// <summary>
	/// Gets whether AES-GCM is supported on the current platform.
	/// </summary>
	public static bool IsSupported => AesGcm.IsSupported;

	/// <inheritdoc />
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);

		if (associatedData.Overlaps(destination))
		{
			EncryptWithOverlappingAssociatedData(nonce, source, destination, tag, associatedData);
			return;
		}

		_internalCrypto.Encrypt(nonce, source, destination, tag, associatedData);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);

		using CryptoBuffer<byte> plaintextBuffer = CryptoBuffer<byte>.ShouldUsePool(source.Length) ? new CryptoBuffer<byte>(source.Length) : new CryptoBuffer<byte>(stackalloc byte[source.Length]);
		Span<byte> plaintext = plaintextBuffer.Span;
		_internalCrypto.Decrypt(nonce, source, tag, plaintext, associatedData);
		plaintext.CopyTo(destination);
	}

	[SkipLocalsInit]
	private void EncryptWithOverlappingAssociatedData(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData)
	{
		using CryptoBuffer<byte> associatedDataBuffer = CryptoBuffer<byte>.ShouldUsePool(associatedData.Length) ? new CryptoBuffer<byte>(associatedData.Length) : new CryptoBuffer<byte>(stackalloc byte[associatedData.Length]);
		Span<byte> associatedDataCopy = associatedDataBuffer.Span;
		associatedData.CopyTo(associatedDataCopy);
		_internalCrypto.Encrypt(nonce, source, destination, tag, associatedDataCopy);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_internalCrypto.Dispose();
	}
}
