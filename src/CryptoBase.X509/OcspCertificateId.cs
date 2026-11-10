namespace CryptoBase.X509;

/// <summary>
/// Represents a CertID (RFC 6960, Sec. 4.1.1): the hashes of the issuer's name and key, and the serial number, that identify a certificate to an OCSP responder.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class OcspCertificateId
{
	private const string Sha1Oid = "1.3.14.3.2.26";
	private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
	private const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
	private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";

	private const int MaxDigestLength = SHA512.HashSizeInBytes;

	private OcspCertificateId(AlgorithmIdentifier hashAlgorithm, ReadOnlyMemory<byte> issuerNameHash, ReadOnlyMemory<byte> issuerKeyHash, ReadOnlyMemory<byte> serialNumber)
	{
		HashAlgorithm = hashAlgorithm;
		IssuerNameHash = issuerNameHash;
		IssuerKeyHash = issuerKeyHash;
		SerialNumber = serialNumber;
	}

	/// <summary>
	/// Gets the algorithm of <see cref="IssuerNameHash" /> and <see cref="IssuerKeyHash" />.
	/// </summary>
	public AlgorithmIdentifier HashAlgorithm { get; }

	/// <summary>
	/// Gets the hash of the DER encoding of the issuer's Name.
	/// </summary>
	public ReadOnlyMemory<byte> IssuerNameHash { get; }

	/// <summary>
	/// Gets the hash of the issuer's public key, without the tag and length of its BIT STRING.
	/// </summary>
	public ReadOnlyMemory<byte> IssuerKeyHash { get; }

	/// <summary>
	/// Gets the serial number of the certificate, the big-endian two's-complement contents of its INTEGER, as those of <see cref="Certificate.SerialNumber" />.
	/// </summary>
	public ReadOnlyMemory<byte> SerialNumber { get; }

	/// <summary>
	/// Determines whether the identifier identifies a certificate, with its own hash algorithm.
	/// </summary>
	/// <remarks>The hash is computed with <see cref="HashAlgorithm" />, which must be SHA-1, SHA-256, SHA-384 or SHA-512 with NULL or absent parameters; the identifier of any other hash identifies no certificate.</remarks>
	/// <param name="certificate">The certificate.</param>
	/// <param name="issuer">The certificate of its issuer.</param>
	/// <returns><see langword="true" /> if the serial number and both hashes are those of the certificate; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="certificate" /> or <paramref name="issuer" /> is <see langword="null" />.</exception>
	public bool Matches(Certificate certificate, Certificate issuer)
	{
		ArgumentNullException.ThrowIfNull(certificate);
		ArgumentNullException.ThrowIfNull(issuer);

		if (!SerialNumber.Span.SequenceEqual(certificate.SerialNumber.Span) || HashAlgorithm.Parameters.Span is not ([] or [0x05, 0x00]))
		{
			return false;
		}

		Span<byte> digest = stackalloc byte[MaxDigestLength];

		if (!TryHash(HashAlgorithm.Oid, certificate.Issuer.Span, digest, out int written) || !IssuerNameHash.Span.SequenceEqual(digest.Slice(0, written)))
		{
			return false;
		}

		TryHash(HashAlgorithm.Oid, issuer.PublicKeyInfo.PublicKey.Span, digest, out written);
		return IssuerKeyHash.Span.SequenceEqual(digest.Slice(0, written));
	}

	// RFC 9919, Sec. 3.1.1, requires SHA-256 of a client.
	internal static OcspCertificateId Create(Certificate certificate, Certificate issuer, HashAlgorithmName hashAlgorithm)
	{
		string oid = hashAlgorithm.Name switch
		{
			null or "SHA256" => Sha256Oid,
			"SHA1" => Sha1Oid,
			_ => throw new NotSupportedException($"The hash algorithm {hashAlgorithm} is not supported for an OCSP certificate identifier.")
		};

		Span<byte> digest = stackalloc byte[MaxDigestLength];
		TryHash(oid, certificate.Issuer.Span, digest, out int written);
		byte[] issuerNameHash = digest.Slice(0, written).ToArray();
		TryHash(oid, issuer.PublicKeyInfo.PublicKey.Span, digest, out written);
		byte[] issuerKeyHash = digest.Slice(0, written).ToArray();

		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier(oid);
			writer.WriteNull();
		}

		DerReader identifier = new(writer.Encode());
		return new OcspCertificateId(AlgorithmIdentifier.Read(ref identifier), issuerNameHash, issuerKeyHash, certificate.SerialNumber);
	}

	// CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING, serialNumber CertificateSerialNumber }; the results are slices of the reader's memory.
	internal static OcspCertificateId Read(ref DerReader reader)
	{
		DerReader sequence = reader.ReadSequence();
		AlgorithmIdentifier hashAlgorithm = AlgorithmIdentifier.Read(ref sequence);
		ReadOnlyMemory<byte> issuerNameHash = sequence.ReadOctetString();
		ReadOnlyMemory<byte> issuerKeyHash = sequence.ReadOctetString();
		ReadOnlyMemory<byte> serialNumber = sequence.ReadIntegerBytes();
		sequence.ThrowIfNotEmpty();
		return new OcspCertificateId(hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber);
	}

	internal void Write(AsnWriter writer)
	{
		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(HashAlgorithm.Encoded.Span);
			writer.WriteOctetString(IssuerNameHash.Span);
			writer.WriteOctetString(IssuerKeyHash.Span);
			writer.WriteInteger(SerialNumber.Span);
		}
	}

	// No digest is empty, so nothing written tells a hash that is not one of the four.
	private static bool TryHash(string oid, ReadOnlySpan<byte> source, Span<byte> destination, out int written)
	{
		written = oid switch
		{
			Sha1Oid => SHA1.HashData(source, destination),
			Sha256Oid => SHA256.HashData(source, destination),
			Sha384Oid => SHA384.HashData(source, destination),
			Sha512Oid => SHA512.HashData(source, destination),
			_ => 0
		};

		return written > 0;
	}
}
