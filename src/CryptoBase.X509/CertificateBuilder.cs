namespace CryptoBase.X509;

/// <summary>
/// Builds X.509 certificates.
/// </summary>
/// <remarks>
/// A certificate is version 3, its validity period is truncated to whole seconds in UTC, and its extensions follow <see cref="Extensions" /> in order.
/// The subject name is DER-encoded, as the <see cref="AsnEncodedData.RawData" /> of an <see cref="X500DistinguishedName" /> such as <c>new X500DistinguishedName("CN=example.com")</c> is, and the <see cref="AsnEncodedData.RawData" /> of the BCL extension types gives extension values.
/// </remarks>
public sealed class CertificateBuilder
{
	private const int MaxSerialNumberLength = 20;
	private const int RandomSerialNumberLength = 16;

	/// <summary>
	/// Initializes a builder for certificates with a subject name.
	/// </summary>
	/// <param name="subjectName">The DER-encoded Name of the subject, which must not be empty and whose attribute values are checked only as single DER elements; the builder holds a copy.</param>
	/// <exception cref="ArgumentException"><paramref name="subjectName" /> is not a DER-encoded Name or is empty.</exception>
	public CertificateBuilder(ReadOnlySpan<byte> subjectName)
	{
		byte[] name = CopyName(subjectName, nameof(subjectName));

		// The subject is also the issuer of a self-signed certificate, which RFC 5280, Sec. 4.1.2.4, requires to be nonempty.
		if (X509Name.IsEmpty(name))
		{
			throw new ArgumentException("The subject name is empty.", nameof(subjectName));
		}

		SubjectName = name;
	}

	/// <summary>
	/// Gets the DER-encoded Name of the subject.
	/// </summary>
	public ReadOnlyMemory<byte> SubjectName { get; }

	/// <summary>
	/// Gets or sets the serial number as an unsigned big-endian integer, or an empty value for a random one of 16 bytes for each certificate.
	/// </summary>
	/// <remarks>
	/// The builder holds a copy of the value set. The INTEGER of a certificate holds it without leading zero bytes, and with the zero byte first that its sign may need, so a positive <see cref="Certificate.SerialNumber" /> sets the same serial number.
	/// </remarks>
	/// <exception cref="ArgumentException">The value set is zero or has more than 159 bits, which do not fit the 20 bytes of an INTEGER that RFC 5280, Sec. 4.1.2.2, allows.</exception>
	public ReadOnlyMemory<byte> SerialNumber
	{
		get;
		set
		{
			ReadOnlySpan<byte> serialNumber = value.Span;
			int start = serialNumber.IndexOfAnyExcept((byte)0);

			// The bytes from the first nonzero one, with a zero byte for the sign if its high bit is set.
			if (!serialNumber.IsEmpty && (start < 0 || serialNumber.Length - start + (serialNumber[start] >> 7) > MaxSerialNumberLength))
			{
				throw new ArgumentException("The serial number must be a positive integer of at most 159 bits.", nameof(value));
			}

			field = serialNumber.ToArray();
		}
	}

	/// <summary>
	/// Gets the extensions to include, in order.
	/// </summary>
	public IList<CertificateExtension> Extensions { get; } = new List<CertificateExtension>();

	/// <summary>
	/// Creates a certificate that a key signs for its own public key, with the subject as the issuer.
	/// </summary>
	/// <param name="key">The key, which must hold the private key; it signs, and its SubjectPublicKeyInfo becomes the certificate's.</param>
	/// <param name="algorithm">The signature algorithm, which <paramref name="key" /> must support.</param>
	/// <param name="notBefore">The start of the validity period.</param>
	/// <param name="notAfter">The end of the validity period, no earlier than <paramref name="notBefore" />.</param>
	/// <returns>The certificate.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="key" /> does not support <paramref name="algorithm" /> or has an invalid SubjectPublicKeyInfo, or <paramref name="notAfter" /> is earlier than <paramref name="notBefore" /> to the second.</exception>
	/// <exception cref="NotSupportedException"><paramref name="algorithm" /> has no X.509 identifier in this version; see <see cref="AlgorithmIdentifier.FromSignatureAlgorithm" />.</exception>
	/// <exception cref="InvalidOperationException"><see cref="Extensions" /> holds <see langword="null" />, two extensions with one identifier or a key usage extension that is not a DER BIT STRING of the nine defined bits with at least one set, as <see cref="Certificate.KeyUsage" /> describes them, or <paramref name="key" /> does not hold the private key.</exception>
	/// <exception cref="CryptographicException">The key store or device that holds the private key failed to sign.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="key" /> has been disposed.</exception>
	public Certificate CreateSelfSigned(ISignatureKey key, SignatureAlgorithm algorithm, DateTimeOffset notBefore, DateTimeOffset notAfter)
	{
		ArgumentNullException.ThrowIfNull(key);

		AlgorithmIdentifier signatureAlgorithm = GetSignatureAlgorithm(key, algorithm);
		(notBefore, notAfter) = TruncateValidity(notBefore, notAfter);
		CertificateExtension[] extensions = CopyExtensions(Extensions);
		SubjectPublicKeyInfo subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key, nameof(key));

		return Issue(SubjectName, signatureAlgorithm, notBefore, notAfter, subjectPublicKeyInfo, extensions, key, algorithm, nameof(key));
	}

	/// <summary>
	/// Creates a certificate that a CA signs for a public key, with the subject of the CA's certificate as the issuer.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The authority key identifier and the subject key identifier extensions (RFC 5280, Sec. 4.2.1.1 and 4.2.1.2) are added, non-critical and in that order after <see cref="Extensions" />, unless <see cref="Extensions" /> holds one with the same identifier. The keyIdentifier of the former is the subject key identifier of <paramref name="issuer" /> and, if it has none, the SHA-1 hash of its subjectPublicKey, and the latter is the SHA-1 hash of the subjectPublicKey of <paramref name="subjectPublicKeyInfo" />, which is method (1) of Sec. 4.2.1.2.
	/// </para>
	/// <para>
	/// The method does not read certification requests: the caller verifies one with <see cref="CertificationRequest.VerifySignature" /> and adds to <see cref="Extensions" /> what it accepts of <see cref="CertificationRequest.RequestedExtensions" />.
	/// </para>
	/// </remarks>
	/// <param name="issuer">The CA's certificate, whose basic constraints extension must assert cA, whose key usage extension, if any, must allow keyCertSign, and whose subject must not be empty.</param>
	/// <param name="issuerKey">The CA's key, which must hold the private key and match the public key of <paramref name="issuer" />, in the algorithm's object identifier and the subjectPublicKey.</param>
	/// <param name="algorithm">The signature algorithm, which <paramref name="issuerKey" /> must support.</param>
	/// <param name="subjectPublicKeyInfo">The public key to certify.</param>
	/// <param name="notBefore">The start of the validity period, no earlier than that of <paramref name="issuer" /> to the second.</param>
	/// <param name="notAfter">The end of the validity period, no earlier than <paramref name="notBefore" /> and no later than that of <paramref name="issuer" /> to the second.</param>
	/// <returns>The certificate.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="issuer" />, <paramref name="issuerKey" /> or <paramref name="subjectPublicKeyInfo" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="issuer" /> is not a CA that may sign certificates or its subject key identifier extension does not decode when the method needs it, <paramref name="issuerKey" /> does not match <paramref name="issuer" />, does not support <paramref name="algorithm" /> or has an invalid SubjectPublicKeyInfo, the id-RSASSA-PSS parameters of the public key of <paramref name="issuer" /> do not allow <paramref name="algorithm" />, or the validity period is out of order or not within that of <paramref name="issuer" />.</exception>
	/// <exception cref="NotSupportedException"><paramref name="algorithm" /> has no X.509 identifier in this version; see <see cref="AlgorithmIdentifier.FromSignatureAlgorithm" />.</exception>
	/// <exception cref="InvalidOperationException"><see cref="Extensions" /> holds <see langword="null" />, two extensions with one identifier or a key usage extension that is not a DER BIT STRING of the nine defined bits with at least one set, as <see cref="Certificate.KeyUsage" /> describes them, or <paramref name="issuerKey" /> does not hold the private key.</exception>
	/// <exception cref="CryptographicException">The key store or device that holds the private key failed to sign.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="issuerKey" /> has been disposed.</exception>
	public Certificate CreateSigned(Certificate issuer, ISignatureKey issuerKey, SignatureAlgorithm algorithm, SubjectPublicKeyInfo subjectPublicKeyInfo, DateTimeOffset notBefore, DateTimeOffset notAfter)
	{
		ArgumentNullException.ThrowIfNull(issuer);
		ArgumentNullException.ThrowIfNull(issuerKey);
		ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);

		AlgorithmIdentifier signatureAlgorithm = GetSignatureAlgorithm(issuerKey, algorithm);
		(notBefore, notAfter) = TruncateValidity(notBefore, notAfter);

		if (notBefore < issuer.NotBefore)
		{
			throw new ArgumentException("The start of the validity period is earlier than the issuer's.", nameof(notBefore));
		}

		if (notAfter > issuer.NotAfter)
		{
			throw new ArgumentException("The end of the validity period is later than the issuer's.", nameof(notAfter));
		}

		if (issuer.DecodedExtensions.BasicConstraints.Value is not { CertificateAuthority: true })
		{
			throw new ArgumentException("The issuer's basic constraints do not assert cA.", nameof(issuer));
		}

		if (issuer.KeyUsage is { } keyUsage && !keyUsage.HasFlag(X509KeyUsageFlags.KeyCertSign))
		{
			throw new ArgumentException("The issuer's key usage does not allow keyCertSign.", nameof(issuer));
		}

		// RFC 5280, Sec. 4.1.2.4, requires a nonempty issuer.
		if (X509Name.IsEmpty(issuer.Subject.Span))
		{
			throw new ArgumentException("The issuer's subject is empty.", nameof(issuer));
		}

		SubjectPublicKeyInfo issuerPublicKeyInfo = ExportSubjectPublicKeyInfo(issuerKey, nameof(issuerKey));

		if (issuerPublicKeyInfo.Algorithm.Oid != issuer.PublicKeyInfo.Algorithm.Oid || !issuerPublicKeyInfo.PublicKey.Span.SequenceEqual(issuer.PublicKeyInfo.PublicKey.Span))
		{
			throw new ArgumentException("The key does not match the issuer's public key.", nameof(issuerKey));
		}

		CheckIssuerKeyParameters(issuer, algorithm);

		CertificateExtension[] extensions = AddKeyIdentifiers(CopyExtensions(Extensions), issuer, subjectPublicKeyInfo);

		return Issue(issuer.Subject, signatureAlgorithm, notBefore, notAfter, subjectPublicKeyInfo, extensions, issuerKey, algorithm, nameof(issuerKey));
	}

	internal static AlgorithmIdentifier GetSignatureAlgorithm(ISignatureKey key, SignatureAlgorithm algorithm)
	{
		if (!key.Supports(algorithm))
		{
			throw new ArgumentException("The key does not support the signature algorithm.", nameof(algorithm));
		}

		return AlgorithmIdentifier.FromSignatureAlgorithm(algorithm);
	}

	internal static byte[] CopyName(ReadOnlySpan<byte> source, string parameterName)
	{
		byte[] name = source.ToArray();

		try
		{
			DerReader reader = new(name);
			X509Name.Read(ref reader);
			reader.ThrowIfNotEmpty();
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The subject name is not a DER-encoded Name.", parameterName, e);
		}

		return name;
	}

	// Decoding the result checks the extensions, so they are checked before signing, the key usage in DER.
	internal static CertificateExtension[] CopyExtensions(IList<CertificateExtension> source)
	{
		CertificateExtension[] extensions = [.. source];

		foreach (CertificateExtension? extension in extensions)
		{
			if (extension is null)
			{
				throw new InvalidOperationException("The extensions include null.");
			}
		}

		try
		{
			Certificate.CheckExtensions(extensions, derKeyUsage: true);
		}
		catch (AsnContentException e)
		{
			throw new InvalidOperationException(e.Message, e);
		}

		return extensions;
	}

	internal static SubjectPublicKeyInfo ExportSubjectPublicKeyInfo(ISignatureKey key, string parameterName)
	{
		byte[] encoded = new byte[key.SubjectPublicKeyInfoLength];
		key.ExportSubjectPublicKeyInfo(encoded);
		return SubjectPublicKeyInfo.Decode(encoded, parameterName);
	}

	// SEQUENCE { toBeSigned, signatureAlgorithm, signature BIT STRING }, the form of a certificate and of a certification request.
	internal static byte[] SignAndEncode(byte[] toBeSigned, AlgorithmIdentifier signatureAlgorithm, ISignatureKey key, SignatureAlgorithm algorithm)
	{
		byte[] signature = new byte[key.GetMaxSignatureLength(algorithm)];
		int signatureLength = key.Sign(algorithm, toBeSigned, signature);

		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(toBeSigned);
			writer.WriteEncodedValue(signatureAlgorithm.Encoded.Span);
			writer.WriteBitString(signature.AsSpan(0, signatureLength));
		}

		return writer.Encode();
	}

	// RFC 4055, Sec. 3.1: the parameters of an id-RSASSA-PSS key in the issuer's certificate limit the signatures that verify with it, whatever the object of the private key allows.
	private static void CheckIssuerKeyParameters(Certificate issuer, SignatureAlgorithm algorithm)
	{
		if (issuer.PublicKeyInfo.Algorithm.Oid is not AlgorithmIdentifier.RsassaPssOid)
		{
			return;
		}

		bool allowed;

		try
		{
			using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(issuer.PublicKeyInfo.Encoded.Span);
			allowed = key.Supports(algorithm);
		}
		catch (Exception e) when (e is ArgumentException or NotSupportedException)
		{
			throw new ArgumentException("The issuer's public key is not an id-RSASSA-PSS key that can be used.", nameof(issuer), e);
		}

		if (!allowed)
		{
			throw new ArgumentException("The issuer's public key does not allow the signature algorithm.", nameof(algorithm));
		}
	}

	private static (DateTimeOffset NotBefore, DateTimeOffset NotAfter) TruncateValidity(DateTimeOffset notBefore, DateTimeOffset notAfter)
	{
		notBefore = X509Time.TruncateToSeconds(notBefore);
		notAfter = X509Time.TruncateToSeconds(notAfter);

		if (notAfter < notBefore)
		{
			throw new ArgumentException("The end of the validity period is earlier than its start.", nameof(notAfter));
		}

		return (notBefore, notAfter);
	}

	private static CertificateExtension[] AddKeyIdentifiers(CertificateExtension[] extensions, Certificate issuer, SubjectPublicKeyInfo subjectPublicKeyInfo)
	{
		bool hasAuthorityKeyIdentifier = false;
		bool hasSubjectKeyIdentifier = false;

		foreach (CertificateExtension extension in extensions)
		{
			hasAuthorityKeyIdentifier |= extension.Oid is DecodedExtensions.AuthorityKeyIdentifierOid;
			hasSubjectKeyIdentifier |= extension.Oid is DecodedExtensions.SubjectKeyIdentifierOid;
		}

		CertificateExtension[] authorityKeyIdentifier = hasAuthorityKeyIdentifier ? [] : [CreateAuthorityKeyIdentifier(issuer)];
		CertificateExtension[] subjectKeyIdentifier = hasSubjectKeyIdentifier ? [] : [CreateSubjectKeyIdentifier(subjectPublicKeyInfo)];
		return [.. extensions, .. authorityKeyIdentifier, .. subjectKeyIdentifier];
	}

	// AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier OPTIONAL, … }, non-critical as RFC 5280, Sec. 4.2.1.1, requires.
	private static CertificateExtension CreateAuthorityKeyIdentifier(Certificate issuer)
	{
		DecodedExtension<ReadOnlyMemory<byte>?> issuerKeyIdentifier = issuer.DecodedExtensions.SubjectKeyIdentifier;

		if (issuerKeyIdentifier.Error is not null)
		{
			throw new ArgumentException("The issuer's subject key identifier is invalid.", nameof(issuer), issuerKeyIdentifier.Error);
		}

		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteOctetString(issuerKeyIdentifier.Value is { } keyIdentifier ? keyIdentifier.Span : SHA1.HashData(issuer.PublicKeyInfo.PublicKey.Span), AuthorityKeyIdentifier.KeyIdentifierTag);
		}

		return new CertificateExtension(DecodedExtensions.AuthorityKeyIdentifierOid, false, writer.Encode());
	}

	// SubjectKeyIdentifier ::= OCTET STRING, non-critical as RFC 5280, Sec. 4.2.1.2, requires; the identifier is its method (1), the SHA-1 hash of the value of the BIT STRING subjectPublicKey.
	private static CertificateExtension CreateSubjectKeyIdentifier(SubjectPublicKeyInfo subjectPublicKeyInfo)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteOctetString(SHA1.HashData(subjectPublicKeyInfo.PublicKey.Span));
		return new CertificateExtension(DecodedExtensions.SubjectKeyIdentifierOid, false, writer.Encode());
	}

	// 126 random bits in 16 bytes whose first is in [0x40, 0x7F], so the INTEGER takes 16 bytes with no zero byte for the sign.
	private static byte[] CreateSerialNumber()
	{
		byte[] serialNumber = new byte[RandomSerialNumberLength];
		RandomNumberGenerator.Fill(serialNumber);
		serialNumber[0] = (byte)(0x40 | serialNumber[0] & 0x3F);
		return serialNumber;
	}

	private Certificate Issue(ReadOnlyMemory<byte> issuerName, AlgorithmIdentifier signatureAlgorithm, DateTimeOffset notBefore, DateTimeOffset notAfter, SubjectPublicKeyInfo subjectPublicKeyInfo, CertificateExtension[] extensions, ISignatureKey key, SignatureAlgorithm algorithm, string keyParameterName)
	{
		byte[] tbsCertificate = WriteTbsCertificate(issuerName.Span, signatureAlgorithm, notBefore, notAfter, subjectPublicKeyInfo, extensions);
		return Certificate.Decode(SignAndEncode(tbsCertificate, signatureAlgorithm, key, algorithm), keyParameterName);
	}

	private byte[] WriteTbsCertificate(ReadOnlySpan<byte> issuerName, AlgorithmIdentifier signatureAlgorithm, DateTimeOffset notBefore, DateTimeOffset notAfter, SubjectPublicKeyInfo subjectPublicKeyInfo, CertificateExtension[] extensions)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			using (writer.PushSequence(Certificate.VersionTag))
			{
				writer.WriteInteger(2);
			}

			ReadOnlySpan<byte> serialNumber = SerialNumber.Span;
			writer.WriteIntegerUnsigned(serialNumber.IsEmpty ? CreateSerialNumber() : serialNumber.Slice(serialNumber.IndexOfAnyExcept((byte)0)));
			writer.WriteEncodedValue(signatureAlgorithm.Encoded.Span);
			writer.WriteEncodedValue(issuerName);

			using (writer.PushSequence())
			{
				X509Time.Write(writer, notBefore);
				X509Time.Write(writer, notAfter);
			}

			writer.WriteEncodedValue(SubjectName.Span);
			writer.WriteEncodedValue(subjectPublicKeyInfo.Encoded.Span);

			if (extensions.Length > 0)
			{
				using (writer.PushSequence(Certificate.ExtensionsTag))
				{
					CertificateExtension.WriteList(writer, extensions);
				}
			}
		}

		return writer.Encode();
	}
}
