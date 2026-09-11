using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.SymmetricCryptos.AeadCryptos;

/// <summary>
/// Provides ChaCha20-Poly1305 authenticated encryption.
/// </summary>
public sealed class ChaCha20Poly1305Crypto : IAeadCrypto
{
	/// <inheritdoc />
	public string Name => @"ChaCha20-Poly1305";

	/// <inheritdoc />
	public int NonceSizeInBytes => NonceSize;

	/// <inheritdoc />
	public int TagSizeInBytes => TagSize;

	private readonly ChaCha20Crypto _chacha20;

	/// <summary>
	/// The required key size, in bytes.
	/// </summary>
	public const int KeySize = 32;

	/// <summary>
	/// The required nonce size, in bytes.
	/// </summary>
	public const int NonceSize = 12;

	/// <summary>
	/// The authentication tag size, in bytes.
	/// </summary>
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> EmptyIV12 => "\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	/// <summary>
	/// Initializes a new instance with the specified key.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
	public ChaCha20Poly1305Crypto(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		_chacha20 = new ChaCha20Crypto(key, EmptyIV12);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);

		_chacha20.SetIV(nonce);
		ChaCha20Poly1305Utils.EncryptAndComputeTag(_chacha20, source, destination, tag, associatedData);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);

		_chacha20.SetIV(nonce);

		_chacha20.SetCounter(0);
		Span<byte> computedTag = stackalloc byte[TagSize];
		ChaCha20Poly1305Utils.ComputeTag(_chacha20, associatedData, source, computedTag);

		ThrowHelper.ThrowIfAuthenticationTagMismatch(computedTag, tag);

		_chacha20.SetCounter(1);
		_chacha20.Update(source, destination);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_chacha20.Dispose();
	}
}
