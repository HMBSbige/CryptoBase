using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

/// <summary>
/// Provides AES-GCM authenticated encryption using <see cref="AesGcm"/> with 12-byte nonces and 16-byte tags.
/// </summary>
/// <param name="key">The 16-, 24-, or 32-byte AES key.</param>
public sealed class DefaultAesGcmCrypto(ReadOnlySpan<byte> key) : IAEADCrypto
{
	/// <inheritdoc />
	public string Name => @"AES-GCM";

	private readonly AesGcm _internalCrypto = new(key, GcmMode128<AesCipher>.TagSize);

	/// <summary>
	/// The required nonce size, in bytes.
	/// </summary>
	public const int NonceSize = 12;

	/// <summary>
	/// Gets whether AES-GCM is supported on the current platform.
	/// </summary>
	public static bool IsSupported => AesGcm.IsSupported;

	/// <inheritdoc />
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Encrypt(nonce, source, destination, tag, associatedData);
	}

	/// <inheritdoc />
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Decrypt(nonce, source, tag, destination, associatedData);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_internalCrypto.Dispose();
	}
}
