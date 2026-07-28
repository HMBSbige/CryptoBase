using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

public sealed class XChaCha20Poly1305Crypto : IAEADCrypto
{
	public string Name => @"XChaCha20-Poly1305";

	private readonly XChaCha20Crypto _chacha20;

	public const int KeySize = 32;
	public const int NonceSize = 24;
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> EmptyIv24 => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	public XChaCha20Poly1305Crypto(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		_chacha20 = new XChaCha20Crypto(key, EmptyIv24);
	}

	[SkipLocalsInit]
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));

		_chacha20.SetIV(nonce);

		_chacha20.SetCounter(1);
		_chacha20.Update(source, destination);

		_chacha20.SetCounter(0);
		ChaCha20Poly1305Utils.ComputeTag(_chacha20, associatedData, destination, tag);
	}

	[SkipLocalsInit]
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));

		_chacha20.SetIV(nonce);

		_chacha20.SetCounter(0);
		Span<byte> computedTag = stackalloc byte[TagSize];
		ChaCha20Poly1305Utils.ComputeTag(_chacha20, associatedData, source, computedTag);

		ThrowHelper.ThrowIfAuthenticationTagMismatch(computedTag, tag);

		_chacha20.SetCounter(1);
		_chacha20.Update(source, destination);
	}

	public void Dispose()
	{
		_chacha20.Dispose();
	}
}
