namespace CryptoBase.X509;

/// <summary>
/// Represents an OCSP response (RFC 6960, Sec. 4.2).
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of RFC 6960, Sec. 4.2.1: an error status has no responseBytes and a successful one does.
/// Decoding does not check the signature, or whether the response is current; a response of another type decodes, with <see cref="ResponseType" /> to tell it apart, and only the members of the status are set.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class OcspResponse
{
	private const string BasicResponseOid = "1.3.6.1.5.5.7.48.1.1";

	private static readonly Asn1Tag ResponseBytesTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag VersionTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag ByNameTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag ByKeyTag = new(TagClass.ContextSpecific, 2, true);
	private static readonly Asn1Tag ResponseExtensionsTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag CertificatesTag = new(TagClass.ContextSpecific, 0, true);

	private OcspResponse(ReadOnlyMemory<byte> encoded)
	{
		Encoded = encoded;
		Responses = [];
		Certificates = [];
		Extensions = [];

		DerReader reader = new(encoded);
		DerReader response = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		Status = ReadStatus(response.ReadEnumeratedBytes().Span);

		if (Status is OcspResponseStatus.Successful)
		{
			DerReader wrapper = response.ReadSequence(ResponseBytesTag);
			DerReader responseBytes = wrapper.ReadSequence();
			wrapper.ThrowIfNotEmpty();
			ResponseType = responseBytes.ReadObjectIdentifier();
			ReadOnlyMemory<byte> value = responseBytes.ReadOctetString();
			responseBytes.ThrowIfNotEmpty();

			if (ResponseType is BasicResponseOid)
			{
				ReadBasicResponse(value);
			}
		}

		response.ThrowIfNotEmpty();
	}

	/// <summary>
	/// Gets the DER encoding of the whole OCSPResponse.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the status of the response.
	/// </summary>
	public OcspResponseStatus Status { get; }

	/// <summary>
	/// Gets the responseType as a dotted-decimal object identifier, or <see langword="null" /> unless <see cref="Status" /> is <see cref="OcspResponseStatus.Successful" />.
	/// </summary>
	public string? ResponseType { get; }

	/// <summary>
	/// Gets the DER encoding of the ResponseData, which the signature covers, or an empty value unless the response is of the basic type.
	/// </summary>
	public ReadOnlyMemory<byte> TbsResponseData { get; private set; }

	/// <summary>
	/// Gets the identifier of the responder, or <see langword="null" /> unless the response is of the basic type.
	/// </summary>
	public OcspResponderId? Responder { get; private set; }

	/// <summary>
	/// Gets the time at which the responder signed the response, in UTC, or <see langword="null" /> unless the response is of the basic type.
	/// </summary>
	public DateTimeOffset? ProducedAt { get; private set; }

	/// <summary>
	/// Gets the status of each certificate, in the order of the encoding; empty unless the response is of the basic type.
	/// </summary>
	public IReadOnlyList<OcspSingleResponse> Responses { get; private set; }

	/// <summary>
	/// Gets the responseExtensions, in the order of the encoding; empty if there are none.
	/// </summary>
	public IReadOnlyList<CertificateExtension> Extensions { get; private set; }

	/// <summary>
	/// Gets the certificates of the certs field that decode, in the order of the encoding; empty if there are none. They are not checked.
	/// </summary>
	public IReadOnlyList<Certificate> Certificates { get; private set; }

	/// <summary>
	/// Gets the nonce, or <see langword="null" /> if the response has none or the nonce is not an OCTET STRING of 1 to 32 bytes.
	/// </summary>
	public ReadOnlyMemory<byte>? Nonce { get; private set; }

	/// <summary>
	/// Gets the algorithm of the responder's signature, or <see langword="null" /> unless the response is of the basic type.
	/// </summary>
	public AlgorithmIdentifier? SignatureAlgorithm { get; private set; }

	/// <summary>
	/// Gets the responder's signature, the bytes of its BIT STRING, or an empty value unless the response is of the basic type.
	/// </summary>
	public ReadOnlyMemory<byte> Signature { get; private set; }

	/// <summary>
	/// Decodes a DER-encoded OCSP response.
	/// </summary>
	/// <param name="source">The response, with nothing after it.</param>
	/// <returns>The response, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded OCSPResponse.</exception>
	public static OcspResponse Decode(ReadOnlySpan<byte> source)
	{
		try
		{
			return new OcspResponse(source.ToArray());
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The OCSP response is invalid.", nameof(source), e);
		}
	}

	/// <summary>
	/// Verifies the responder's signature on the ResponseData.
	/// </summary>
	/// <remarks>To tell an algorithm that the package does not support from a wrong signature, call <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> on <see cref="SignatureAlgorithm" />.</remarks>
	/// <param name="responderKey">The responder's public key.</param>
	/// <returns><see langword="true" /> if the response is of the basic type, <see cref="SignatureAlgorithm" /> names a signature algorithm that <paramref name="responderKey" /> supports and the signature is valid with it; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="responderKey" /> is <see langword="null" />.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="responderKey" /> has been disposed.</exception>
	public bool VerifySignature(ISignatureKey responderKey)
	{
		ArgumentNullException.ThrowIfNull(responderKey);

		return SignatureAlgorithm is { } identifier
			&& identifier.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm)
			&& responderKey.Supports(algorithm)
			&& responderKey.Verify(algorithm, TbsResponseData.Span, Signature.Span);
	}

	// OCSPResponseStatus ::= ENUMERATED { successful (0), malformedRequest (1), internalError (2), tryLater (3), sigRequired (5), unauthorized (6) }.
	private static OcspResponseStatus ReadStatus(ReadOnlySpan<byte> contents)
	{
		return contents is [var value] && value <= 6 && value is not 4 ? (OcspResponseStatus)value : throw new AsnContentException("The response status is not defined.");
	}

	// BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, signatureAlgorithm AlgorithmIdentifier, signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }.
	private void ReadBasicResponse(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		DerReader basic = reader.ReadSequence();
		reader.ThrowIfNotEmpty();

		DerReader data = basic.ReadSequence(out ReadOnlyMemory<byte> tbsResponseData);
		TbsResponseData = tbsResponseData;
		SignatureAlgorithm = AlgorithmIdentifier.Read(ref basic);
		Signature = basic.ReadBitString();

		if (basic.PeekTagIs(CertificatesTag))
		{
			Certificates = ReadCertificates(ref basic);
		}

		basic.ThrowIfNotEmpty();
		ReadResponseData(ref data);
	}

	// ResponseData ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, responderID ResponderID, producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse, responseExtensions [1] EXPLICIT Extensions OPTIONAL }. The only version, v1, is the default, which DER omits, so a version is an error.
	private void ReadResponseData(ref DerReader data)
	{
		if (data.PeekTagIs(VersionTag))
		{
			throw new AsnContentException();
		}

		Responder = ReadResponderId(ref data);
		ProducedAt = X509Time.ReadGeneralizedTime(ref data);

		DerReader responses = data.ReadSequence();
		List<OcspSingleResponse> list = [];

		while (responses.HasData)
		{
			list.Add(OcspSingleResponse.Read(ref responses));
		}

		Responses = list.AsReadOnly();

		if (data.PeekTagIs(ResponseExtensionsTag))
		{
			Extensions = CertificateExtension.ReadList(ref data, ResponseExtensionsTag);
			ReadNonce();
		}

		data.ThrowIfNotEmpty();
	}

	// ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }, explicit as the module's default tagging and CHOICE require.
	private static OcspResponderId ReadResponderId(ref DerReader data)
	{
		if (data.PeekTagIs(ByNameTag))
		{
			DerReader wrapper = data.ReadSequence(ByNameTag);
			ReadOnlyMemory<byte> name = X509Name.Read(ref wrapper);
			wrapper.ThrowIfNotEmpty();
			return new OcspResponderId(name, null);
		}

		DerReader key = data.ReadSequence(ByKeyTag);
		ReadOnlyMemory<byte> hash = key.ReadOctetString();
		key.ThrowIfNotEmpty();
		return new OcspResponderId(null, hash);
	}

	// The certs field: SEQUENCE OF Certificate, of which each element must be DER, and those that are not certificates are skipped.
	private static IReadOnlyList<Certificate> ReadCertificates(ref DerReader basic)
	{
		DerReader wrapper = basic.ReadSequence(CertificatesTag);
		DerReader sequence = wrapper.ReadSequence();
		wrapper.ThrowIfNotEmpty();
		List<Certificate> certificates = [];

		while (sequence.HasData)
		{
			ReadOnlyMemory<byte> element = sequence.ReadEncodedValue();

			try
			{
				certificates.Add(Certificate.Read(element));
			}
			catch (AsnContentException)
			{
			}
		}

		return certificates.AsReadOnly();
	}

	// Nonce ::= OCTET STRING (SIZE(1..32)) (RFC 8954, Sec. 2.1), which is left null if it has another form.
	private void ReadNonce()
	{
		IReadOnlyList<CertificateExtension> extensions = Extensions;

		for (int i = 0; i < extensions.Count; ++i)
		{
			CertificateExtension extension = extensions[i];

			if (extension.Oid is not OcspRequest.NonceOid)
			{
				continue;
			}

			try
			{
				DerReader reader = new(extension.Value);
				ReadOnlyMemory<byte> nonce = reader.ReadOctetString();

				if (!reader.HasData && nonce.Length is >= 1 and <= 32)
				{
					Nonce = nonce;
				}
			}
			catch (AsnContentException)
			{
			}

			return;
		}
	}
}
