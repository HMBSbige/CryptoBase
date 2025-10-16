using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.Poly1305;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

public sealed class ChaCha20Poly1305Crypto : IAEADCrypto
{
	public string Name => @"ChaCha20-Poly1305";

	private readonly ChaCha20Crypto _chacha20;

	public const int KeySize = 32;
	public const int NonceSize = 12;
	public const int TagSize = 16;

	private static ReadOnlySpan<byte> Init => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	public ChaCha20Poly1305Crypto(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		_chacha20 = StreamCryptoCreate.ChaCha20(key);
	}

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
		Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));

		_chacha20.SetIV(nonce);

		_chacha20.SetCounter(1);
		_chacha20.Update(source, destination);

		Span<byte> buffer = stackalloc byte[Poly1305.KeySize];
		_chacha20.SetCounter(0);
		_chacha20.Update(Init, buffer);
		using Poly1305 poly1305 = new(buffer);

		poly1305.Update(associatedData);
		poly1305.Update(destination);

		Span<byte> block = stackalloc byte[Poly1305.BlockSize];
		BinaryPrimitives.WriteUInt64LittleEndian(block, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(block[8..], (ulong)source.Length);
		poly1305.Update(block);

		poly1305.GetMac(tag);
	}

	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
		Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));

		_chacha20.SetIV(nonce);

		Span<byte> buffer = stackalloc byte[Poly1305.KeySize];
		_chacha20.SetCounter(0);
		_chacha20.Update(Init, buffer);
		using Poly1305 poly1305 = new(buffer);

		poly1305.Update(associatedData);
		poly1305.Update(source);

		Span<byte> block = stackalloc byte[Poly1305.TagSize];
		BinaryPrimitives.WriteUInt64LittleEndian(block, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(block[8..], (ulong)source.Length);

		poly1305.Update(block);

		poly1305.GetMac(block);

		ThrowHelper.ThrowIfAuthenticationTagMismatch(block, tag);

		_chacha20.SetCounter(1);
		_chacha20.Update(source, destination);
	}

	public void Dispose()
	{
		_chacha20.Dispose();
	}
}
