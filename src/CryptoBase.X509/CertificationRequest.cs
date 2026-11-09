namespace CryptoBase.X509;

/// <summary>
/// Represents a PKCS #10 certification request (RFC 2986).
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of RFC 2986, Sec. 4: the attributes field must be present, though it may be empty, the extensionRequest attribute (RFC 2985, Sec. 5.4.2) may appear only once, with one nonempty sequence of distinct extensions, and a key usage extension must decode as in <see cref="Certificate.KeyUsage" />.
/// The values of the other attributes remain in <see cref="Encoded" />. Decoding does not check whether the algorithms are supported or whether the signature is valid; see <see cref="VerifySignature" />.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class CertificationRequest
{
	internal const string ExtensionRequestOid = "1.2.840.113549.1.9.14";

	internal static readonly Asn1Tag AttributesTag = new(TagClass.ContextSpecific, 0, true);

	private const string PemLabel = "CERTIFICATE REQUEST";

	private CertificationRequest(ReadOnlyMemory<byte> encoded)
	{
		Encoded = encoded;
		DerReader request = DerReader.ReadSoleSequence(encoded);

		DerReader info = request.ReadSequence(out ReadOnlyMemory<byte> certificationRequestInfo);
		CertificationRequestInfo = certificationRequestInfo;
		SignatureAlgorithm = AlgorithmIdentifier.Read(ref request);
		Signature = request.ReadBitString();
		request.ThrowIfNotEmpty();

		if (info.ReadInt32() is not 0)
		{
			throw new AsnContentException();
		}

		Subject = X509Name.Read(ref info);
		PublicKeyInfo = SubjectPublicKeyInfo.Read(ref info);
		RequestedExtensions = ReadAttributes(ref info);
		info.ThrowIfNotEmpty();
	}

	/// <summary>
	/// Gets the DER encoding of the whole certification request.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the DER encoding of the CertificationRequestInfo, which the signature covers.
	/// </summary>
	public ReadOnlyMemory<byte> CertificationRequestInfo { get; }

	/// <summary>
	/// Gets the DER encoding of the subject Name, which may be empty.
	/// </summary>
	public ReadOnlyMemory<byte> Subject { get; }

	/// <summary>
	/// Gets the public key to certify.
	/// </summary>
	public SubjectPublicKeyInfo PublicKeyInfo { get; }

	/// <summary>
	/// Gets the algorithm of the requester's signature.
	/// </summary>
	public AlgorithmIdentifier SignatureAlgorithm { get; }

	/// <summary>
	/// Gets the requester's signature, the bytes of its BIT STRING.
	/// </summary>
	public ReadOnlyMemory<byte> Signature { get; }

	/// <summary>
	/// Gets the extensions of the extensionRequest attribute (RFC 2985, Sec. 5.4.2), in the order of the encoding; empty if there is no such attribute.
	/// </summary>
	public IReadOnlyList<CertificateExtension> RequestedExtensions { get; }

	/// <summary>
	/// Decodes a DER-encoded certification request.
	/// </summary>
	/// <param name="source">The certification request, with nothing after it.</param>
	/// <returns>The certification request, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded certification request.</exception>
	public static CertificationRequest Decode(ReadOnlySpan<byte> source)
	{
		return Decode(source.ToArray(), nameof(source));
	}

	/// <summary>
	/// Decodes the first PEM block (RFC 7468) labeled CERTIFICATE REQUEST in a text.
	/// </summary>
	/// <remarks>Other blocks and the text around the blocks are ignored.</remarks>
	/// <param name="source">The text.</param>
	/// <returns>The certification request.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has no CERTIFICATE REQUEST block, or the first one is not a DER-encoded certification request.</exception>
	public static CertificationRequest DecodePem(ReadOnlySpan<char> source)
	{
		X509PemReader reader = new(source, PemLabel);
		return reader.TryRead(out byte[]? encoded) ? Decode(encoded, nameof(source)) : throw new ArgumentException("The text holds no CERTIFICATE REQUEST block.", nameof(source));
	}

	/// <summary>
	/// Verifies the requester's signature on the CertificationRequestInfo.
	/// </summary>
	/// <remarks>To tell an algorithm that the package does not support from a wrong signature, call <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> on <see cref="SignatureAlgorithm" />.</remarks>
	/// <param name="key">The requester's public key, which <see cref="PublicKeyInfo" /> holds.</param>
	/// <returns><see langword="true" /> if <see cref="SignatureAlgorithm" /> names a signature algorithm that <paramref name="key" /> supports and the signature is valid with it; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="key" /> has been disposed.</exception>
	public bool VerifySignature(ISignatureKey key)
	{
		ArgumentNullException.ThrowIfNull(key);

		return SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm)
			&& key.Supports(algorithm)
			&& key.Verify(algorithm, CertificationRequestInfo.Span, Signature.Span);
	}

	// encoded is owned by the new instance.
	internal static CertificationRequest Decode(byte[] encoded, string parameterName)
	{
		try
		{
			return new CertificationRequest(encoded);
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The certification request is invalid.", parameterName, e);
		}
	}

	// attributes [0] IMPLICIT SET OF Attribute, where Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET SIZE (1..MAX) OF ANY } (RFC 2986, Sec. 4.1), and the result is the value of extensionRequest, or empty without it.
	private static IReadOnlyList<CertificateExtension> ReadAttributes(ref DerReader info)
	{
		DerReader attributes = info.ReadSetOf(AttributesTag);
		IReadOnlyList<CertificateExtension>? extensions = null;

		while (attributes.HasData)
		{
			DerReader attribute = attributes.ReadSequence();
			string type = attribute.ReadObjectIdentifier();
			DerReader values = attribute.ReadSetOf();
			attribute.ThrowIfNotEmpty();
			values.ThrowIfEmpty();

			if (type is not ExtensionRequestOid)
			{
				while (values.HasData)
				{
					values.ReadEncodedValue();
				}

				continue;
			}

			if (extensions is not null)
			{
				throw new AsnContentException("The attributes include extensionRequest more than once.");
			}

			// extensionRequest is SINGLE VALUE TRUE (RFC 2985, Sec. 5.4.2).
			extensions = Certificate.ReadExtensionSequence(ref values);
			values.ThrowIfNotEmpty();
			Certificate.CheckExtensions(extensions);
		}

		return extensions ?? [];
	}
}
