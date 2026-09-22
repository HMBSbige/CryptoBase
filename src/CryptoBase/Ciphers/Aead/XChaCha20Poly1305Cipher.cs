using CryptoBase.Ciphers.Streams;

namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Provides XChaCha20-Poly1305 authenticated encryption.
/// </summary>
public sealed class XChaCha20Poly1305Cipher : IAeadCipher<XChaCha20Poly1305Cipher>
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = XChaCha20Cipher.KeySize;

	/// <inheritdoc />
	public static XChaCha20Poly1305Cipher Create(scoped ReadOnlySpan<byte> key)
	{
		return new XChaCha20Poly1305Cipher(key);
	}

	/// <inheritdoc />
	public static int NonceSize => XChaCha20Cipher.IVSize;

	/// <inheritdoc />
	public static int TagSize => 16;

	private readonly XChaCha20Cipher _chacha20;

	private static ReadOnlySpan<byte> EmptyIV24 => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	/// <summary>
	/// Initializes a new instance with the specified key.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
	public XChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		_chacha20 = new XChaCha20Cipher(key, EmptyIV24);
	}

	/// <inheritdoc />
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		_chacha20.InitializeNonce(nonce);
		ChaCha20Poly1305Utils.EncryptAndComputeTag(_chacha20, source, destination, tag, associatedData);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		_chacha20.InitializeNonce(nonce);
		Span<byte> computedTag = stackalloc byte[TagSize];
		return ChaCha20Poly1305Utils.TryDecrypt(_chacha20, source, tag, destination, associatedData, computedTag);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_chacha20.Dispose();
	}
}
