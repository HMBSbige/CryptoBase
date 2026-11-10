using System.Collections.ObjectModel;

namespace CryptoBase.X509;

/// <summary>
/// Represents an X.509 certificate (RFC 5280).
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of RFC 5280, Sec. 4.1: the signature fields inside and outside the TBSCertificate must match, the issuer and subject must be Names, the version must allow the fields that are present, an extension may appear only once, and the signature and the subjectPublicKey must be whole bytes. The attribute values of the Names and the parameters of the algorithm identifiers need only be single DER elements; their contents are not checked.
/// It decodes the key usage extension, and does not check whether the algorithms are supported, what the other extensions hold or whether the certificate is valid now; a certificate with an unrecognized critical extension decodes, and leaves the decision to the validator.
/// </para>
/// <para>
/// The authority key identifier, subject key identifier and subject alternative name extensions decode on first use instead, so a certificate in which one of them is malformed still decodes, and the methods that return them report the error.
/// </para>
/// <para>
/// An instance holds its own copy of the encoding, and the members return slices of it. Instances are immutable, so they may be used concurrently; the extensions that decode on first use are decoded once and kept, also when threads ask for them at once.
/// </para>
/// </remarks>
public sealed class Certificate
{
	internal const string KeyUsageOid = "2.5.29.15";
	private const string PemLabel = "CERTIFICATE";

	internal static readonly Asn1Tag VersionTag = new(TagClass.ContextSpecific, 0, true);
	internal static readonly Asn1Tag ExtensionsTag = new(TagClass.ContextSpecific, 3, true);

	private static readonly Asn1Tag IssuerUniqueIdTag = new(TagClass.ContextSpecific, 1);
	private static readonly Asn1Tag SubjectUniqueIdTag = new(TagClass.ContextSpecific, 2);

	private Certificate(ReadOnlyMemory<byte> encoded)
	{
		Encoded = encoded;
		DerReader certificate = DerReader.ReadSoleSequence(encoded);

		DerReader tbs = certificate.ReadSequence(out ReadOnlyMemory<byte> tbsCertificate);
		TbsCertificate = tbsCertificate;
		SignatureAlgorithm = AlgorithmIdentifier.Read(ref certificate);
		Signature = certificate.ReadBitString();
		certificate.ThrowIfNotEmpty();

		Version = 1;

		// DER omits the default version, v1.
		if (tbs.TryReadSequence(VersionTag, out DerReader version))
		{
			Version = version.ReadInt32() switch
			{
				1 => 2,
				2 => 3,
				_ => throw new AsnContentException()
			};
			version.ThrowIfNotEmpty();
		}

		SerialNumber = tbs.ReadIntegerBytes();

		// The outer signature algorithm is an AlgorithmIdentifier, so the same bytes are one.
		if (!tbs.ReadEncodedValue().Span.SequenceEqual(SignatureAlgorithm.Encoded.Span))
		{
			throw new AsnContentException();
		}

		Issuer = X509Name.Read(ref tbs);
		DerReader validity = tbs.ReadSequence();
		NotBefore = X509Time.Read(ref validity);
		NotAfter = X509Time.Read(ref validity);
		validity.ThrowIfNotEmpty();
		Subject = X509Name.Read(ref tbs);
		PublicKeyInfo = SubjectPublicKeyInfo.Read(ref tbs);

		if (Version > 1)
		{
			foreach (Asn1Tag tag in (ReadOnlySpan<Asn1Tag>)[IssuerUniqueIdTag, SubjectUniqueIdTag])
			{
				if (tbs.PeekTagIs(tag))
				{
					tbs.ReadBitString(tag, wholeBytes: false);
				}
			}
		}

		// extensions [3] EXPLICIT Extensions.
		if (Version is 3 && tbs.TryReadSequence(ExtensionsTag, out DerReader wrapper))
		{
			Extensions = ReadExtensionSequence(ref wrapper);
			wrapper.ThrowIfNotEmpty();
			KeyUsage = CheckExtensions(Extensions);
		}
		else
		{
			Extensions = [];
		}

		tbs.ThrowIfNotEmpty();
	}

	/// <summary>
	/// Gets the DER encoding of the whole certificate.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the DER encoding of the TBSCertificate, which the signature covers.
	/// </summary>
	public ReadOnlyMemory<byte> TbsCertificate { get; }

	/// <summary>
	/// Gets the version: 1, 2 or 3.
	/// </summary>
	public int Version { get; }

	/// <summary>
	/// Gets the serial number, the big-endian two's-complement contents of its INTEGER.
	/// </summary>
	/// <remarks>
	/// RFC 5280 asks certificate users to tolerate the negative and zero serial numbers that some CAs issue, so decoding accepts any INTEGER.
	/// Unlike <see cref="CertificateBuilder.SerialNumber" />, which is unsigned, the contents start with a zero byte when the high bit of a positive number is set.
	/// </remarks>
	public ReadOnlyMemory<byte> SerialNumber { get; }

	/// <summary>
	/// Gets the DER encoding of the issuer Name.
	/// </summary>
	public ReadOnlyMemory<byte> Issuer { get; }

	/// <summary>
	/// Gets the DER encoding of the subject Name.
	/// </summary>
	public ReadOnlyMemory<byte> Subject { get; }

	/// <summary>
	/// Gets the start of the validity period, in UTC.
	/// </summary>
	public DateTimeOffset NotBefore { get; }

	/// <summary>
	/// Gets the end of the validity period, in UTC.
	/// </summary>
	public DateTimeOffset NotAfter { get; }

	/// <summary>
	/// Gets the subject's public key.
	/// </summary>
	/// <remarks>The caller imports the key from <see cref="SubjectPublicKeyInfo.Encoded" /> as it chooses: with <see cref="ISignatureKey{TSelf}.ImportSubjectPublicKeyInfo" /> of a key type, or with the <c>SignatureKey</c> class of the <c>CryptoBase</c> package as the type of its algorithm.</remarks>
	public SubjectPublicKeyInfo PublicKeyInfo { get; }

	/// <summary>
	/// Gets the extensions, in the order of the encoding; empty if there are none.
	/// </summary>
	public IReadOnlyList<CertificateExtension> Extensions { get; }

	/// <summary>
	/// Gets the uses that the key usage extension (RFC 5280, Sec. 4.2.1.3) allows the subject's key, or <see langword="null" /> if the certificate has no such extension, which allows any use.
	/// </summary>
	/// <remarks>
	/// Certificate validators, including <see cref="PlatformCertificateValidator" />, do not check it; the caller checks the uses that it needs.
	/// Decoding requires the extension to be a BIT STRING of the nine defined bits with at least one set. Trailing zero bits, which DER drops, are accepted.
	/// </remarks>
	public X509KeyUsageFlags? KeyUsage { get; }

	/// <summary>
	/// Gets the algorithm of the issuer's signature.
	/// </summary>
	public AlgorithmIdentifier SignatureAlgorithm { get; }

	/// <summary>
	/// Gets the issuer's signature, the bytes of its BIT STRING.
	/// </summary>
	public ReadOnlyMemory<byte> Signature { get; }

	// The extensions that decode on first use. Threads that race decode them alike, and all use the instance stored first.
	internal DecodedExtensions DecodedExtensions
	{
		get
		{
			if (Volatile.Read(ref field) is { } decoded)
			{
				return decoded;
			}

			DecodedExtensions created = new(Extensions);
			return Interlocked.CompareExchange(ref field, created, null) ?? created;
		}
	}

	/// <summary>
	/// Decodes a DER-encoded certificate.
	/// </summary>
	/// <param name="source">The certificate, with nothing after it.</param>
	/// <returns>The certificate, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded certificate.</exception>
	public static Certificate Decode(ReadOnlySpan<byte> source)
	{
		return Decode(source.ToArray(), nameof(source));
	}

	/// <summary>
	/// Decodes the first PEM block (RFC 7468) labeled CERTIFICATE in a text.
	/// </summary>
	/// <remarks>Other blocks and the text around the blocks are ignored.</remarks>
	/// <param name="source">The text.</param>
	/// <returns>The certificate.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has no CERTIFICATE block, or the first one is not a DER-encoded certificate.</exception>
	public static Certificate DecodePem(ReadOnlySpan<char> source)
	{
		return Decode(X509PemReader.ReadFirst(source, PemLabel, nameof(source)), nameof(source));
	}

	/// <summary>
	/// Decodes every PEM block (RFC 7468) labeled CERTIFICATE in a text, such as a certificate chain.
	/// </summary>
	/// <remarks>Other blocks and the text around the blocks are ignored.</remarks>
	/// <param name="source">The text.</param>
	/// <returns>The certificates, in the order of the text; empty if there are none.</returns>
	/// <exception cref="ArgumentException">A CERTIFICATE block is not a DER-encoded certificate.</exception>
	public static Certificate[] DecodePemAll(ReadOnlySpan<char> source)
	{
		return X509PemReader.ReadAll(source, PemLabel, static encoded => Decode(encoded, nameof(source)));
	}

	/// <summary>
	/// Verifies the issuer's signature on the TBSCertificate.
	/// </summary>
	/// <remarks>To tell an algorithm that the package does not support from a wrong signature, call <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> on <see cref="SignatureAlgorithm" />.</remarks>
	/// <param name="issuerKey">The issuer's public key.</param>
	/// <returns><see langword="true" /> if <see cref="SignatureAlgorithm" /> names a signature algorithm that <paramref name="issuerKey" /> supports and the signature is valid with it; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="issuerKey" /> is <see langword="null" />.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="issuerKey" /> has been disposed.</exception>
	public bool VerifySignature(ISignatureKey issuerKey)
	{
		ArgumentNullException.ThrowIfNull(issuerKey);

		return SignatureAlgorithm.VerifySignature(issuerKey, TbsCertificate.Span, Signature.Span);
	}

	/// <summary>
	/// Gets the value of the authority key identifier extension (RFC 5280, Sec. 4.2.1.1), which identifies the issuer's key.
	/// </summary>
	/// <remarks>The first call decodes the extension, as <see cref="AuthorityKeyIdentifier.Decode" /> does, and later calls return the same instance. Calls may be concurrent.</remarks>
	/// <returns>The value, whose members are slices of <see cref="Encoded" />, or <see langword="null" /> if the certificate has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded AuthorityKeyIdentifier.</exception>
	public AuthorityKeyIdentifier? GetAuthorityKeyIdentifier()
	{
		return DecodedExtensions.AuthorityKeyIdentifier.GetValueOrThrow("authority key identifier");
	}

	/// <summary>
	/// Gets the subject key identifier extension (RFC 5280, Sec. 4.2.1.2), which identifies the subject's key.
	/// </summary>
	/// <remarks>The first call decodes the extension, and later calls return the same value. Calls may be concurrent.</remarks>
	/// <returns>The bytes of the OCTET STRING, a slice of <see cref="Encoded" />, or <see langword="null" /> if the certificate has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded OCTET STRING.</exception>
	public ReadOnlyMemory<byte>? GetSubjectKeyIdentifier()
	{
		return DecodedExtensions.SubjectKeyIdentifier.GetValueOrThrow("subject key identifier");
	}

	/// <summary>
	/// Gets the value of the subject alternative name extension (RFC 5280, Sec. 4.2.1.6), the identities bound to the subject.
	/// </summary>
	/// <remarks>The first call decodes the extension, as <see cref="SubjectAlternativeName.Decode" /> does, and later calls return the same instance. Calls may be concurrent.</remarks>
	/// <returns>The value, whose IP addresses are slices of <see cref="Encoded" />, or <see langword="null" /> if the certificate has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded GeneralNames.</exception>
	public SubjectAlternativeName? GetSubjectAlternativeName()
	{
		return DecodedExtensions.SubjectAlternativeName.GetValueOrThrow("subject alternative name");
	}

	/// <summary>
	/// Determines whether the subject alternative name extension identifies a host name, as RFC 9525 specifies for TLS and DTLS.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The rules are those of <see cref="SubjectAlternativeName.MatchesHostName" />: a DNS name, in A-labels or labels that are not ASCII and that the platform's IDNA conversion accepts and leaves as they are, with one trailing dot allowed, matches a dNSName entry or a wildcard entry for one label, and an IP address matches an iPAddress entry; the subject's common name is not used.
	/// </para>
	/// <para>
	/// Unlike <see cref="GetSubjectAlternativeName" />, the method does not throw for an extension that does not decode. It checks <paramref name="hostName" /> first, so an invalid host name throws whatever the extension holds. Calls may be concurrent.
	/// </para>
	/// </remarks>
	/// <param name="hostName">The host name: a DNS name or an IP address.</param>
	/// <returns><see cref="HostNameMatch.Match" /> if an entry identifies <paramref name="hostName" />; <see cref="HostNameMatch.Mismatch" /> if none does or the certificate has no such extension; <see cref="HostNameMatch.MalformedExtension" /> if the extension does not decode.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="hostName" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="hostName" /> is neither a DNS name nor an IP address.</exception>
	public HostNameMatch MatchHostName(string hostName)
	{
		ArgumentNullException.ThrowIfNull(hostName);

		HostName reference = HostName.Parse(hostName, nameof(hostName));
		DecodedExtension<SubjectAlternativeName> subjectAlternativeName = DecodedExtensions.SubjectAlternativeName;

		if (subjectAlternativeName.Error is not null)
		{
			return HostNameMatch.MalformedExtension;
		}

		return subjectAlternativeName.Value?.Matches(reference) is true ? HostNameMatch.Match : HostNameMatch.Mismatch;
	}

	/// <summary>
	/// Gets the value of the authority information access extension (RFC 5280, Sec. 4.2.2.1), which locates the issuer's certificates and its OCSP responders.
	/// </summary>
	/// <remarks>The first call decodes the extension, and later calls return the same instance. Calls may be concurrent.</remarks>
	/// <returns>The value, or <see langword="null" /> if the certificate has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded AuthorityInfoAccessSyntax.</exception>
	public AuthorityInformationAccess? GetAuthorityInformationAccess()
	{
		return DecodedExtensions.AuthorityInformationAccess.GetValueOrThrow("authority information access");
	}

	/// <summary>
	/// Gets the value of the CRL distribution points extension (RFC 5280, Sec. 4.2.1.13), which locates the CRLs that cover the certificate.
	/// </summary>
	/// <remarks>The first call decodes the extension, and later calls return the same list. Calls may be concurrent.</remarks>
	/// <returns>The distribution points, in the order of the encoding, or <see langword="null" /> if the certificate has no such extension.</returns>
	/// <exception cref="CryptographicException">The extension is not a DER-encoded CRLDistributionPoints.</exception>
	public IReadOnlyList<CrlDistributionPoint>? GetCrlDistributionPoints()
	{
		return DecodedExtensions.CrlDistributionPoints.GetValueOrThrow("CRL distribution points");
	}

	// The value of the basic constraints extension (RFC 5280, Sec. 4.2.1.9), decoded on first use, or null without it; CryptographicException if it does not decode.
	internal BasicConstraints? GetBasicConstraints()
	{
		return DecodedExtensions.BasicConstraints.GetValueOrThrow("basic constraints");
	}

	// The value of the extended key usage extension (RFC 5280, Sec. 4.2.1.12), decoded on first use, or null without it; CryptographicException if it does not decode.
	internal ExtendedKeyUsage? GetExtendedKeyUsage()
	{
		return DecodedExtensions.ExtendedKeyUsage.GetValueOrThrow("extended key usage");
	}

	// A certificate that holds a slice of memory that outlives it, without a copy; AsnContentException if it is not DER-encoded.
	internal static Certificate Read(ReadOnlyMemory<byte> encoded)
	{
		return new Certificate(encoded);
	}

	// encoded is owned by the new instance.
	internal static Certificate Decode(byte[] encoded, string parameterName)
	{
		try
		{
			return new Certificate(encoded);
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The certificate is invalid.", parameterName, e);
		}
	}

	// Each extnID at most once, and a key usage extension that decodes, in DER alone with derKeyUsage; the result is its key usage, or null without it. CertificateBuilder checks its extensions with this before signing, so that it writes DER.
	internal static X509KeyUsageFlags? CheckExtensions(IReadOnlyList<CertificateExtension> extensions, bool derKeyUsage = false)
	{
		X509KeyUsageFlags? keyUsage = null;
		HashSet<string> oids = new(extensions.Count, StringComparer.Ordinal);

		for (int i = 0; i < extensions.Count; ++i)
		{
			string oid = extensions[i].Oid;

			if (!oids.Add(oid))
			{
				throw new AsnContentException($"The extensions include {oid} more than once.");
			}

			if (oid == KeyUsageOid)
			{
				try
				{
					keyUsage = ReadKeyUsage(extensions[i].Value.Span, derKeyUsage);
				}
				catch (AsnContentException e)
				{
					throw new AsnContentException("The key usage extension is invalid.", e);
				}
			}
		}

		return keyUsage;
	}

	// KeyUsage ::= BIT STRING { digitalSignature (0), …, decipherOnly (8) }, of which RFC 5280 requires at least one. Bits 0 through 7 are the first byte from its most significant bit, and bit 8 is the most significant bit of the second, as in X509KeyUsageFlags.
	// DER drops the trailing zero bits (X.690, Sec. 11.2.2), but some CA certificates in use keep them, so trailing zeros are accepted, even in whole bytes, unless der asks for DER; the unused bits must still be zero.
	private static X509KeyUsageFlags ReadKeyUsage(ReadOnlySpan<byte> source, bool der)
	{
		if (!AsnDecoder.TryReadPrimitiveBitString(source, AsnEncodingRules.DER, out int unusedBits, out ReadOnlySpan<byte> bits, out int consumed)
			|| consumed != source.Length
			|| bits.Length is 0
			|| der && (bits.Length > 2 || (bits[^1] >> unusedBits & 1) is 0))
		{
			throw new AsnContentException();
		}

		X509KeyUsageFlags usage = (X509KeyUsageFlags)DerReader.ReadNineNamedBits(bits);
		return usage is not X509KeyUsageFlags.None ? usage : throw new AsnContentException();
	}

	// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
	internal static ReadOnlyCollection<CertificateExtension> ReadExtensionSequence(ref DerReader reader)
	{
		DerReader sequence = reader.ReadSequence();
		sequence.ThrowIfEmpty();

		// Enough for nearly every certificate, so that the list grows at most once.
		List<CertificateExtension> extensions = new(16);

		while (sequence.HasData)
		{
			extensions.Add(CertificateExtension.Read(ref sequence));
		}

		return extensions.AsReadOnly();
	}
}
