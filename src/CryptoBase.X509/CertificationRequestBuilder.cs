namespace CryptoBase.X509;

/// <summary>
/// Builds PKCS #10 certification requests (RFC 2986).
/// </summary>
/// <remarks>
/// The subject name is DER-encoded, as the <see cref="AsnEncodedData.RawData" /> of an <see cref="X500DistinguishedName" /> such as <c>new X500DistinguishedName("CN=example.com")</c> is, and the <see cref="AsnEncodedData.RawData" /> of the BCL extension types gives extension values.
/// </remarks>
public sealed class CertificationRequestBuilder
{
	/// <summary>
	/// Initializes a builder for certification requests with a subject name.
	/// </summary>
	/// <param name="subjectName">The DER-encoded Name of the subject, which may be empty; the builder holds a copy.</param>
	/// <exception cref="ArgumentException"><paramref name="subjectName" /> is not a DER-encoded Name.</exception>
	public CertificationRequestBuilder(ReadOnlySpan<byte> subjectName)
	{
		SubjectName = CertificateBuilder.CopyName(subjectName, nameof(subjectName));
	}

	/// <summary>
	/// Gets the DER-encoded Name of the subject.
	/// </summary>
	public ReadOnlyMemory<byte> SubjectName { get; }

	/// <summary>
	/// Gets the extensions to request, in order, which an extensionRequest attribute (RFC 2985, Sec. 5.4.2) holds; without any, the request has no such attribute.
	/// </summary>
	public IList<CertificateExtension> Extensions { get; } = new List<CertificateExtension>();

	/// <summary>
	/// Creates a certification request for a key, which signs it.
	/// </summary>
	/// <param name="key">The key, which must hold the private key; it signs, and its SubjectPublicKeyInfo becomes the request's.</param>
	/// <param name="algorithm">The signature algorithm, which <paramref name="key" /> must support.</param>
	/// <returns>The certification request.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="key" /> does not support <paramref name="algorithm" /> or has an invalid SubjectPublicKeyInfo.</exception>
	/// <exception cref="NotSupportedException"><paramref name="algorithm" /> has no X.509 identifier in this version; see <see cref="AlgorithmIdentifier.FromSignatureAlgorithm" />.</exception>
	/// <exception cref="InvalidOperationException"><see cref="Extensions" /> holds <see langword="null" />, two extensions with one identifier or a key usage extension that is not a DER BIT STRING of the nine defined bits with at least one set, as <see cref="Certificate.KeyUsage" /> describes them, or <paramref name="key" /> does not hold the private key.</exception>
	/// <exception cref="CryptographicException">The key store or device that holds the private key failed to sign.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="key" /> has been disposed.</exception>
	public CertificationRequest Create(ISignatureKey key, SignatureAlgorithm algorithm)
	{
		ArgumentNullException.ThrowIfNull(key);

		AlgorithmIdentifier signatureAlgorithm = CertificateBuilder.GetSignatureAlgorithm(key, algorithm);
		CertificateExtension[] extensions = CertificateBuilder.CopyExtensions(Extensions);
		SubjectPublicKeyInfo publicKeyInfo = CertificateBuilder.ExportSubjectPublicKeyInfo(key, nameof(key));
		byte[] certificationRequestInfo = WriteCertificationRequestInfo(publicKeyInfo, extensions);

		return CertificationRequest.Decode(CertificateBuilder.SignAndEncode(certificationRequestInfo, signatureAlgorithm, key, algorithm), nameof(key));
	}

	private byte[] WriteCertificationRequestInfo(SubjectPublicKeyInfo publicKeyInfo, CertificateExtension[] extensions)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteInteger(0);
			writer.WriteEncodedValue(SubjectName.Span);
			writer.WriteEncodedValue(publicKeyInfo.Encoded.Span);

			using (writer.PushSetOf(CertificationRequest.AttributesTag))
			{
				if (extensions.Length > 0)
				{
					using (writer.PushSequence())
					{
						writer.WriteObjectIdentifier(CertificationRequest.ExtensionRequestOid);

						using (writer.PushSetOf())
						using (writer.PushSequence())
						{
							foreach (CertificateExtension extension in extensions)
							{
								extension.Write(writer);
							}
						}
					}
				}
			}
		}

		return writer.Encode();
	}
}
