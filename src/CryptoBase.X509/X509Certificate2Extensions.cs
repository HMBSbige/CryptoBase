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
	/// The certificate's key must be ECDSA on P-256, P-384 or P-521. The result is a <see cref="PlatformEcdsaKey" /> whether or not the platform exports the private key, so the private key stays with the platform.
	/// To sign with another implementation, the caller exports the private key, where the platform allows it, and imports it as that implementation, as SignatureKey.TryImportPrivateKey of CryptoBase does for its types.
	/// </para>
	/// <para>
	/// Each call returns a new instance, which the caller disposes; it does not depend on <paramref name="certificate" /> afterwards.
	/// </para>
	/// </remarks>
	/// <param name="certificate">The certificate.</param>
	/// <returns>A key that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="certificate" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="certificate" /> has no private key.</exception>
	/// <exception cref="NotSupportedException">The key is not ECDSA on P-256, P-384 or P-521.</exception>
	/// <exception cref="CryptographicException">The platform cannot open the private key.</exception>
	public static ISignatureKey GetSignaturePrivateKey(this X509Certificate2 certificate)
	{
		ArgumentNullException.ThrowIfNull(certificate);

		if (!certificate.HasPrivateKey)
		{
			throw new ArgumentException("The certificate has no private key.", nameof(certificate));
		}

		ECDsa key = certificate.GetECDsaPrivateKey() ?? throw new NotSupportedException("Only ECDSA private keys are supported.");

		try
		{
			return new PlatformEcdsaKey(key);
		}
		catch
		{
			key.Dispose();
			throw;
		}
	}
}
