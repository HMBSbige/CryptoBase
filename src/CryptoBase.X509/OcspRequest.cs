namespace CryptoBase.X509;

/// <summary>
/// Represents an OCSP request (RFC 6960, Sec. 4.1) for the status of one certificate, as the RFC 9919 profile describes it.
/// </summary>
/// <remarks>
/// <para>
/// The request is unsigned, has no requestorName, and holds one Request whose CertID uses SHA-256 unless the caller chooses SHA-1.
/// A responder that follows RFC 9919 may answer a request with a nonce with a response without one.
/// </para>
/// <para>
/// RFC 9654, Sec. 2.1, has a requester use a nonce of at least 32 bytes. A responder that follows it may answer a longer nonce without one, and a responder that follows RFC 8954 rejects a longer nonce as malformed, so 32 bytes is the length to use.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class OcspRequest
{
	internal const string NonceOid = "1.3.6.1.5.5.7.48.1.2";

	// Nonce ::= OCTET STRING(SIZE(1..128)) (RFC 9654, Sec. 2.1).
	internal const int MaxNonceLength = 128;

	private static readonly Asn1Tag RequestExtensionsTag = new(TagClass.ContextSpecific, 2, true);

	private OcspRequest(byte[] encoded, OcspCertificateId certificateId, ReadOnlyMemory<byte>? nonce)
	{
		Encoded = encoded;
		CertificateId = certificateId;
		Nonce = nonce;
	}

	/// <summary>
	/// Gets the DER encoding of the OCSPRequest.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the CertID of the request.
	/// </summary>
	public OcspCertificateId CertificateId { get; }

	/// <summary>
	/// Gets the nonce that the request carries, or <see langword="null" /> if it has none.
	/// </summary>
	public ReadOnlyMemory<byte>? Nonce { get; }

	/// <summary>
	/// Creates a request for the status of a certificate.
	/// </summary>
	/// <param name="certificate">The certificate.</param>
	/// <param name="issuer">The certificate of its issuer, whose key the CertID hashes.</param>
	/// <param name="nonce">The nonce, up to 128 bytes (RFC 9654, Sec. 2.1); empty for no nonce.</param>
	/// <param name="hashAlgorithm">The hash of the CertID, <see cref="HashAlgorithmName.SHA1" /> or <see cref="HashAlgorithmName.SHA256" />; the default is SHA-256.</param>
	/// <returns>The request.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="certificate" /> or <paramref name="issuer" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="nonce" /> is longer than 128 bytes.</exception>
	/// <exception cref="NotSupportedException"><paramref name="hashAlgorithm" /> is neither SHA-1 nor SHA-256.</exception>
	public static OcspRequest Create(Certificate certificate, Certificate issuer, ReadOnlySpan<byte> nonce = default, HashAlgorithmName hashAlgorithm = default)
	{
		ArgumentNullException.ThrowIfNull(certificate);
		ArgumentNullException.ThrowIfNull(issuer);

		if (nonce.Length > MaxNonceLength)
		{
			throw new ArgumentException($"A nonce must not be longer than {MaxNonceLength} bytes.", nameof(nonce));
		}

		OcspCertificateId certificateId = OcspCertificateId.Create(certificate, issuer, hashAlgorithm);
		AsnWriter writer = new(AsnEncodingRules.DER);

		// OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }, and TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request, requestExtensions [2] EXPLICIT Extensions OPTIONAL }, whose version takes its default, which DER omits.
		using (writer.PushSequence())
		using (writer.PushSequence())
		{
			using (writer.PushSequence())
			using (writer.PushSequence())
			{
				certificateId.Write(writer);
			}

			if (!nonce.IsEmpty)
			{
				WriteNonce(writer, nonce);
			}
		}

		// Assigned only when present: a null in a conditional with a byte[] would convert to an empty value.
		ReadOnlyMemory<byte>? copy = null;

		if (!nonce.IsEmpty)
		{
			copy = nonce.ToArray();
		}

		return new OcspRequest(writer.Encode(), certificateId, copy);
	}

	// One Extension id-pkix-ocsp-nonce, whose extnValue is the DER of Nonce ::= OCTET STRING (RFC 9654, Sec. 2.1), not critical.
	private static void WriteNonce(AsnWriter writer, ReadOnlySpan<byte> nonce)
	{
		AsnWriter value = new(AsnEncodingRules.DER);
		value.WriteOctetString(nonce);

		using (writer.PushSequence(RequestExtensionsTag))
		using (writer.PushSequence())
		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier(NonceOid);
			writer.WriteOctetString(value.Encode());
		}
	}
}
