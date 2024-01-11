using CryptoBase.Abstractions.SymmetricCryptos;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

public class DefaultChaCha20Poly1305Crypto(ReadOnlySpan<byte> key) : IAEADCrypto
{
	public static bool IsSupported => ChaCha20Poly1305.IsSupported;

	public string Name => @"ChaCha20-Poly1305";

	private readonly ChaCha20Poly1305 _internalCrypto = new(key);

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Encrypt(nonce, source, destination, tag, associatedData);
	}

	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Decrypt(nonce, source, tag, destination, associatedData);
	}

	public void Dispose()
	{
		_internalCrypto.Dispose();
		GC.SuppressFinalize(this);
	}
}
