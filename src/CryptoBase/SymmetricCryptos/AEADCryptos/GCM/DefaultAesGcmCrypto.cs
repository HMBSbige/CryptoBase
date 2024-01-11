using CryptoBase.Abstractions.SymmetricCryptos;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.AEADCryptos.GCM;

public class DefaultAesGcmCrypto(ReadOnlySpan<byte> key) : IAEADCrypto
{
	public string Name => @"AES-GCM";

	private readonly AesGcm _internalCrypto = new(key, GcmCryptoMode.TagSize);

	public const int NonceSize = 12;

	public static bool IsSupported => AesGcm.IsSupported;

	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source,
		Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Encrypt(nonce, source, destination, tag, associatedData);
	}

	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag,
		Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Decrypt(nonce, source, tag, destination, associatedData);
	}

	public void Dispose()
	{
		_internalCrypto.Dispose();
		GC.SuppressFinalize(this);
	}
}
