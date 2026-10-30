using CryptoBase.Internal;
using System.Collections.ObjectModel;

namespace CryptoBase.X509;

/// <summary>
/// Represents an X.509 certificate (RFC 5280).
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of RFC 5280, Sec. 4.1: the signature fields inside and outside the TBSCertificate must match, the issuer and subject must be Names, the version must allow the fields that are present, an extension may appear only once, and the signature and the subjectPublicKey must be whole bytes.
/// It decodes the key usage extension, and does not check whether the algorithms are supported, what the other extensions hold or whether the certificate is valid now; a certificate with an unrecognized critical extension decodes, and leaves the decision to the validator.
/// </para>
/// <para>
/// An instance holds its own copy of the encoding, and the members return slices of it. Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class Certificate
{
	private const string KeyUsageOid = "2.5.29.15";
	private const string PemLabel = "CERTIFICATE";

	internal static readonly Asn1Tag VersionTag = new(TagClass.ContextSpecific, 0, true);
	internal static readonly Asn1Tag ExtensionsTag = new(TagClass.ContextSpecific, 3, true);

	private static readonly Asn1Tag IssuerUniqueIdTag = new(TagClass.ContextSpecific, 1);
	private static readonly Asn1Tag SubjectUniqueIdTag = new(TagClass.ContextSpecific, 2);

	private Certificate(ReadOnlyMemory<byte> encoded)
	{
		Encoded = encoded;
		DerReader reader = new(encoded);
		DerReader certificate = reader.ReadSequence();
		reader.ThrowIfNotEmpty();

		DerReader tbs = certificate.ReadSequence(out ReadOnlyMemory<byte> tbsCertificate);
		TbsCertificate = tbsCertificate;
		SignatureAlgorithm = AlgorithmIdentifier.Read(ref certificate);
		Signature = certificate.ReadBitString();
		certificate.ThrowIfNotEmpty();

		Version = 1;

		// DER omits the default version, v1.
		if (tbs.PeekTagIs(VersionTag))
		{
			DerReader version = tbs.ReadSequence(VersionTag);
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

		if (Version is 3 && tbs.PeekTagIs(ExtensionsTag))
		{
			Extensions = ReadExtensions(ref tbs);
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
	/// Decoding requires the extension to be a DER BIT STRING of the nine defined bits with at least one set.
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
		PemReader reader = new(source);

		while (reader.TryRead(out ReadOnlySpan<char> label, out ReadOnlySpan<char> base64Data, out int decodedLength))
		{
			if (label.SequenceEqual(PemLabel))
			{
				return DecodePemBlock(base64Data, decodedLength, nameof(source));
			}
		}

		throw new ArgumentException("The text holds no CERTIFICATE block.", nameof(source));
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
		PemReader reader = new(source);
		List<Certificate> certificates = [];

		while (reader.TryRead(out ReadOnlySpan<char> label, out ReadOnlySpan<char> base64Data, out int decodedLength))
		{
			if (label.SequenceEqual(PemLabel))
			{
				certificates.Add(DecodePemBlock(base64Data, decodedLength, nameof(source)));
			}
		}

		return [.. certificates];
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

		return SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm)
			&& issuerKey.Supports(algorithm)
			&& issuerKey.Verify(algorithm, TbsCertificate.Span, Signature.Span);
	}

	// The block decodes into the array that the certificate keeps.
	private static Certificate DecodePemBlock(ReadOnlySpan<char> base64Data, int decodedLength, string parameterName)
	{
		byte[] encoded = GC.AllocateUninitializedArray<byte>(decodedLength);
		PemReader.Decode(base64Data, encoded);
		return Decode(encoded, parameterName);
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

	// Each extnID at most once, and a key usage extension that decodes; the result is its key usage, or null without it. CertificateBuilder checks its extensions with this before signing.
	internal static X509KeyUsageFlags? CheckExtensions(IReadOnlyList<CertificateExtension> extensions)
	{
		X509KeyUsageFlags? keyUsage = null;

		for (int i = 0; i < extensions.Count; ++i)
		{
			string oid = extensions[i].Oid;

			// A certificate has few extensions, so a linear search finds a repeated one.
			for (int j = 0; j < i; ++j)
			{
				if (extensions[j].Oid == oid)
				{
					throw new AsnContentException($"The extensions include {oid} more than once.");
				}
			}

			if (oid == KeyUsageOid)
			{
				try
				{
					keyUsage = ReadKeyUsage(extensions[i].Value.Span);
				}
				catch (AsnContentException e)
				{
					throw new AsnContentException("The key usage extension is invalid.", e);
				}
			}
		}

		return keyUsage;
	}

	// KeyUsage ::= BIT STRING { digitalSignature (0), …, decipherOnly (8) }. DER drops the trailing zero bits, so the last bit is set, and RFC 5280 requires at least one. Bits 0 through 7 are the first byte from its most significant bit, and bit 8 is the most significant bit of the second, as in X509KeyUsageFlags.
	private static X509KeyUsageFlags ReadKeyUsage(ReadOnlySpan<byte> source)
	{
		if (!AsnDecoder.TryReadPrimitiveBitString(source, AsnEncodingRules.DER, out int unusedBits, out ReadOnlySpan<byte> bits, out int consumed)
			|| consumed != source.Length
			|| bits.Length is 0 or > 2
			|| (bits[^1] >> unusedBits & 1) is 0
			|| bits is [_, var high] && (high & 0x7F) is not 0)
		{
			throw new AsnContentException();
		}

		return (X509KeyUsageFlags)(bits[0] | (bits.Length > 1 ? bits[1] << 8 : 0));
	}

	// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
	private static ReadOnlyCollection<CertificateExtension> ReadExtensions(ref DerReader tbs)
	{
		DerReader wrapper = tbs.ReadSequence(ExtensionsTag);
		DerReader sequence = wrapper.ReadSequence();
		wrapper.ThrowIfNotEmpty();
		sequence.ThrowIfEmpty();
		List<CertificateExtension> extensions = [];

		while (sequence.HasData)
		{
			extensions.Add(CertificateExtension.Read(ref sequence));
		}

		return extensions.AsReadOnly();
	}
}
