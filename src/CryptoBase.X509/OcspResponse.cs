namespace CryptoBase.X509;

/// <summary>
/// Represents an OCSP response (RFC 6960, Sec. 4.2): an <see cref="Error" />, an <see cref="Other" />, or a <see cref="Basic" />.
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of RFC 6960, Sec. 4.2.1: an error status has no responseBytes and a successful one does.
/// Decoding does not check the signature, or whether the response is current;
/// a response with an error status decodes as an <see cref="Error" />, which has the status alone, a successful one of the basic type as a <see cref="Basic" />, and a successful one of another type as an <see cref="Other" />, with <see cref="Other.ResponseType" /> to tell it apart and its response left unread.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public closed class OcspResponse
{
	private const string BasicResponseOid = "1.3.6.1.5.5.7.48.1.1";

	private static readonly Asn1Tag ResponseBytesTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag VersionTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag ByNameTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag ByKeyTag = new(TagClass.ContextSpecific, 2, true);
	private static readonly Asn1Tag ResponseExtensionsTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag CertificatesTag = new(TagClass.ContextSpecific, 0, true);

	private protected OcspResponse(ReadOnlyMemory<byte> encoded, OcspResponseStatus status)
	{
		Encoded = encoded;
		Status = status;
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
	/// Decodes a DER-encoded OCSP response.
	/// </summary>
	/// <param name="source">The response, with nothing after it.</param>
	/// <returns>The response, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded OCSPResponse.</exception>
	public static OcspResponse Decode(ReadOnlySpan<byte> source)
	{
		try
		{
			return Read(source.ToArray());
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The OCSP response is invalid.", nameof(source), e);
		}
	}

	// OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus, responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }, and ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }.
	private static OcspResponse Read(ReadOnlyMemory<byte> encoded)
	{
		DerReader reader = DerReader.ReadSoleSequence(encoded);
		OcspResponseStatus status = ReadStatus(reader.ReadEnumeratedBytes().Span);
		OcspResponse response;

		if (status is OcspResponseStatus.Successful)
		{
			DerReader responseBytes = reader.ReadExplicit(ResponseBytesTag).ReadSequence();
			string responseType = responseBytes.ReadObjectIdentifier();
			ReadOnlyMemory<byte> value = responseBytes.ReadOctetString();
			responseBytes.ThrowIfNotEmpty();
			response = responseType is BasicResponseOid ? new Basic(encoded, value) : new Other(encoded, responseType);
		}
		else
		{
			response = new Error(encoded, status);
		}

		reader.ThrowIfNotEmpty();
		return response;
	}

	// OCSPResponseStatus ::= ENUMERATED { successful (0), malformedRequest (1), internalError (2), tryLater (3), sigRequired (5), unauthorized (6) }.
	private static OcspResponseStatus ReadStatus(ReadOnlySpan<byte> contents)
	{
		return contents is [var value] && value <= 6 && value is not 4 ? (OcspResponseStatus)value : throw new AsnContentException("The response status is not defined.");
	}

	// ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }, explicit as the module's default tagging and CHOICE require.
	private static OcspResponderId ReadResponderId(ref DerReader data)
	{
		if (data.TryReadExplicit(ByNameTag, out DerReader name))
		{
			return new OcspResponderId.ByName(X509Name.Read(ref name));
		}

		return new OcspResponderId.ByKey(data.ReadExplicit(ByKeyTag).ReadOctetString());
	}

	// The certs field: SEQUENCE OF Certificate.
	// Each element must be a DER element, and those that do not decode as certificates are skipped.
	private static IReadOnlyList<Certificate> ReadCertificates(ref DerReader basic)
	{
		DerReader sequence = basic.ReadExplicit(CertificatesTag).ReadSequence();
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

	// Nonce ::= OCTET STRING(SIZE(1..128)) (RFC 9654, Sec. 2.1), or null if it has another form.
	private static ReadOnlyMemory<byte>? ReadNonce(IReadOnlyList<CertificateExtension> extensions)
	{
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

				if (!reader.HasData && nonce.Length is >= 1 and <= OcspRequest.MaxNonceLength)
				{
					return nonce;
				}
			}
			catch (AsnContentException)
			{
			}

			return null;
		}

		return null;
	}

	/// <summary>
	/// Represents a response with an error status: <see cref="OcspResponse.Status" /> is not <see cref="OcspResponseStatus.Successful" />, and the response has nothing else.
	/// </summary>
	public sealed class Error : OcspResponse
	{
		internal Error(ReadOnlyMemory<byte> encoded, OcspResponseStatus status) : base(encoded, status)
		{
		}
	}

	/// <summary>
	/// Represents a successful response of another type than the basic, whose response is not read.
	/// </summary>
	public sealed class Other : OcspResponse
	{
		internal Other(ReadOnlyMemory<byte> encoded, string responseType) : base(encoded, OcspResponseStatus.Successful)
		{
			ResponseType = responseType;
		}

		/// <summary>
		/// Gets the responseType as a dotted-decimal object identifier.
		/// </summary>
		public string ResponseType { get; }
	}

	/// <summary>
	/// Represents a successful response of the basic type, id-pkix-ocsp-basic: a BasicOCSPResponse (RFC 6960, Sec. 4.2.1).
	/// </summary>
	public sealed class Basic : OcspResponse
	{
		// BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, signatureAlgorithm AlgorithmIdentifier, signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }.
		internal Basic(ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> value) : base(encoded, OcspResponseStatus.Successful)
		{
			DerReader basic = DerReader.ReadSoleSequence(value);

			DerReader data = basic.ReadSequence(out ReadOnlyMemory<byte> tbsResponseData);
			TbsResponseData = tbsResponseData;
			SignatureAlgorithm = AlgorithmIdentifier.Read(ref basic);
			Signature = basic.ReadBitString();
			Certificates = basic.PeekTagIs(CertificatesTag) ? ReadCertificates(ref basic) : [];
			basic.ThrowIfNotEmpty();

			// ResponseData ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, responderID ResponderID, producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse, responseExtensions [1] EXPLICIT Extensions OPTIONAL }.
			// The only version, v1, is the default, which DER omits, so a version is an error.
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
			Extensions = data.PeekTagIs(ResponseExtensionsTag) ? CertificateExtension.ReadList(ref data, ResponseExtensionsTag) : [];
			Nonce = ReadNonce(Extensions);
			data.ThrowIfNotEmpty();
		}

		/// <summary>
		/// Gets the DER encoding of the ResponseData, which the signature covers.
		/// </summary>
		public ReadOnlyMemory<byte> TbsResponseData { get; }

		/// <summary>
		/// Gets the identifier of the responder.
		/// </summary>
		public OcspResponderId Responder { get; }

		/// <summary>
		/// Gets the time at which the responder signed the response, in UTC.
		/// </summary>
		public DateTimeOffset ProducedAt { get; }

		/// <summary>
		/// Gets the status of each certificate, in the order of the encoding.
		/// </summary>
		public IReadOnlyList<OcspSingleResponse> Responses { get; }

		/// <summary>
		/// Gets the responseExtensions, in the order of the encoding; empty if there are none.
		/// </summary>
		public IReadOnlyList<CertificateExtension> Extensions { get; }

		/// <summary>
		/// Gets the certificates of the certs field that decode, in the order of the encoding; empty if there are none.
		/// They are not checked.
		/// </summary>
		public IReadOnlyList<Certificate> Certificates { get; }

		/// <summary>
		/// Gets the nonce, or <see langword="null" /> if the response has none or the nonce is not an OCTET STRING of 1 to 128 bytes.
		/// </summary>
		public ReadOnlyMemory<byte>? Nonce { get; }

		/// <summary>
		/// Gets the algorithm of the responder's signature.
		/// </summary>
		public AlgorithmIdentifier SignatureAlgorithm { get; }

		/// <summary>
		/// Gets the responder's signature, the bytes of its BIT STRING.
		/// </summary>
		public ReadOnlyMemory<byte> Signature { get; }

		/// <summary>
		/// Verifies the responder's signature on the ResponseData.
		/// </summary>
		/// <remarks>
		/// To tell an algorithm that the package does not support from a wrong signature, call <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> on <see cref="SignatureAlgorithm" />.
		/// This method verifies the signature alone; whether the key belongs to a responder authorized to sign the response is what <see cref="FindResponder" /> tells.
		/// </remarks>
		/// <param name="responderKey">The responder's public key.</param>
		/// <returns>
		/// <see langword="true" /> if <see cref="SignatureAlgorithm" /> names a signature algorithm that <paramref name="responderKey" /> supports and the signature is valid with it;
		/// otherwise, <see langword="false" />.
		/// </returns>
		/// <exception cref="ArgumentNullException"><paramref name="responderKey" /> is <see langword="null" />.</exception>
		/// <exception cref="ObjectDisposedException"><paramref name="responderKey" /> has been disposed.</exception>
		public bool VerifySignature(ISignatureKey responderKey)
		{
			ArgumentNullException.ThrowIfNull(responderKey);

			return SignatureAlgorithm.VerifySignature(responderKey, TbsResponseData.Span, Signature.Span);
		}

		/// <summary>
		/// Finds the certificate of the authorized responder that signed the response for the certificates that <paramref name="issuer" /> issued (RFC 6960, Sec. 4.2.2.2): <paramref name="issuer" /> itself, or a delegated responder's certificate among <see cref="Certificates" />.
		/// </summary>
		/// <remarks>
		/// <para>
		/// The signature algorithm of the response must pass the policy of <see cref="TrustAnchorCertificateValidator" />.
		/// <paramref name="issuer" /> signed the response if <see cref="Responder" /> names it and its key verifies the signature.
		/// A delegated responder's certificate must be named by <see cref="Responder" /> and issued by <paramref name="issuer" />: its issuer must be the subject of <paramref name="issuer" />, byte for byte, and the key of <paramref name="issuer" /> must verify its signature;
		/// its basic constraints, extended key usage, subject alternative name, name constraints, authority key identifier, subject key identifier, ocsp-nocheck and noRevAvail extensions, those that it has, must decode;
		/// its extensions must follow the rules of noRevAvail and ocsp-nocheck (RFC 9608, Sec. 3), and include an extended key usage with id-kp-OCSPSigning and no critical extension other than basic constraints, key usage, extended key usage, subject alternative name and ocsp-nocheck;
		/// a key usage extension, if it has one, must assert digitalSignature;
		/// its signature algorithm and key must pass the policy of <see cref="TrustAnchorCertificateValidator" />, with an RSA modulus of at least 2048 bits;
		/// and its key must verify the signature of the response.
		/// It is checked against <paramref name="issuer" /> alone, not on a path, so no name constraints or certificate policies apply to it.
		/// A byName <see cref="Responder" /> matches a subject by the rules of RFC 5280, Sec. 7.1, but names that the package cannot find to be the same, such as values that differ only in the case of a letter beyond ASCII, count as different, and the signer is then not found;
		/// a byKey one matches by the SHA-1 hash of the subject's public key.
		/// At most 8 certificates of <see cref="Certificates" /> that <see cref="Responder" /> names are tried.
		/// The work grows with the number of certificates in <see cref="Certificates" />, so a caller bounds the length of a response from an untrusted source, as <see cref="TrustAnchorCertificateValidator" /> does at 64 KiB.
		/// </para>
		/// <para>
		/// <paramref name="issuer" /> is taken as a certificate that the caller trusts: neither the policy on its key nor its validity period is checked, which the validation of its own path does.
		/// </para>
		/// <para>
		/// The method checks no time: not the validity period of the certificate that it returns, not the thisUpdate and nextUpdate of the responses, and not <see cref="ProducedAt" />.
		/// Nor does it check which certificates the response covers, which <see cref="OcspCertificateId.Matches" /> tells, or whether a delegated responder's certificate is revoked.
		/// The response may be relied on only within the validity period of the certificate that the method returns, as for <paramref name="issuer" /> itself.
		/// <see cref="TrustAnchorCertificateValidator" /> checks the signer, the times and the responder's certificate at the time of the validation.
		/// </para>
		/// <para>
		/// Keys are imported with <paramref name="importPublicKey" /> as <see cref="TrustAnchorCertificateValidator" /> imports them: an RSA key that it does not support is imported with <see cref="PlatformRsaKey.ImportSubjectPublicKeyInfo" />, and a key for which it throws <see cref="NotSupportedException" />, <see cref="ArgumentException" /> or <see cref="CryptographicException" /> gives a problem, while other exceptions escape.
		/// The method disposes the keys that it imports.
		/// </para>
		/// </remarks>
		/// <param name="issuer">The certificate of the CA that issued the certificates that the response is about, which the caller trusts.</param>
		/// <param name="importPublicKey">The importer of public keys, which turns a DER-encoded SubjectPublicKeyInfo into a key that verifies signatures, as for <see cref="TrustAnchorCertificateValidator" />.</param>
		/// <param name="problem">When the method returns <see langword="null" />, why no certificate is an authorized responder that signed the response; otherwise, <see langword="null" />.</param>
		/// <returns><paramref name="issuer" />, the same instance, if it signed the response; otherwise, the delegated responder's certificate that signed it, or <see langword="null" /> if there is none.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="issuer" /> or <paramref name="importPublicKey" /> is <see langword="null" />.</exception>
		/// <exception cref="InvalidOperationException"><paramref name="importPublicKey" /> returned <see langword="null" />.</exception>
		public Certificate? FindResponder(Certificate issuer, Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey, out string? problem)
		{
			ArgumentNullException.ThrowIfNull(issuer);
			ArgumentNullException.ThrowIfNull(importPublicKey);

			problem = RevocationChecker.CheckResponder(this, issuer, importPublicKey, CertificateAlgorithmPolicy.DefaultMinRsaKeySize, null, out Certificate? responder);
			return responder;
		}
	}
}
