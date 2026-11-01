namespace CryptoBase.X509;

/// <summary>
/// Provides <see cref="ISignatureKey" /> access to the private key of an <see cref="X509Certificate2" />.
/// </summary>
public static class X509Certificate2Extensions
{
	/// <summary>
	/// Gets the private key of a certificate as a signature key that signs through the platform.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The certificate's key must be ECDSA on P-256, P-384 or P-521, or RSA whose algorithm is rsaEncryption. The result is a <see cref="PlatformEcdsaKey" /> or a <see cref="PlatformRsaKey" /> whether or not the platform exports the private key, so the private key stays with the platform.
	/// To sign with another implementation, the caller exports the private key, where the platform allows it, and imports it as that implementation, as SignatureKey.TryImportPrivateKey of CryptoBase does for its types.
	/// </para>
	/// <para>
	/// An RSA key signs once, or twice if it fails to make an RSASSA-PSS signature, to learn whether it makes RSASSA-PSS signatures, as <see cref="PlatformRsaKey(RSA)" /> describes; a key store or device may ask the user for a PIN or consent then, or count the signatures.
	/// To sign nothing, the caller passes the key of <see cref="RSACertificateExtensions.GetRSAPrivateKey" /> to <see cref="PlatformRsaKey(RSA, ReadOnlySpan{SignatureAlgorithm})" /> with the algorithms that it signs with.
	/// </para>
	/// <para>
	/// Each call returns a new instance, which the caller disposes; it does not depend on <paramref name="certificate" /> afterwards.
	/// </para>
	/// </remarks>
	/// <param name="certificate">The certificate.</param>
	/// <returns>A key that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="certificate" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="certificate" /> has no private key.</exception>
	/// <exception cref="NotSupportedException">The key is neither ECDSA on P-256, P-384 or P-521 nor RSA with a modulus of 512 to 16384 bits and a public exponent of at most 33 bits.</exception>
	/// <exception cref="CryptographicException">The platform cannot open the private key, or an RSA private key fails to sign.</exception>
	public static ISignatureKey GetSignaturePrivateKey(this X509Certificate2 certificate)
	{
		ArgumentNullException.ThrowIfNull(certificate);

		if (!certificate.HasPrivateKey)
		{
			throw new ArgumentException("The certificate has no private key.", nameof(certificate));
		}

		if (certificate.GetECDsaPrivateKey() is { } ecdsa)
		{
			return Adopt(ecdsa, static key => new PlatformEcdsaKey(key));
		}

		if (certificate.GetRSAPrivateKey() is { } rsa)
		{
			return Adopt(rsa, static key => new PlatformRsaKey(key));
		}

		throw new NotSupportedException("Only ECDSA and RSA private keys are supported.");
	}

	// The new instance owns key, which is disposed if create throws.
	private static ISignatureKey Adopt<T>(T key, Func<T, ISignatureKey> create) where T : AsymmetricAlgorithm
	{
		try
		{
			return create(key);
		}
		catch
		{
			key.Dispose();
			throw;
		}
	}
}
