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
	/// <param name="subjectName">The DER-encoded Name of the subject, which must not be empty; the builder holds a copy.</param>
	/// <exception cref="ArgumentException"><paramref name="subjectName" /> is not a DER-encoded Name or is empty.</exception>
	public CertificateBuilder(ReadOnlySpan<byte> subjectName)
	{
		byte[] name = subjectName.ToArray();

		try
		{
			DerReader reader = new(name);
			X509Name.Read(ref reader);
			reader.ThrowIfNotEmpty();
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The subject name is not a DER-encoded Name.", nameof(subjectName), e);
		}

		// The subject is also the issuer of a self-signed certificate, which RFC 5280, Sec. 4.1.2.4, requires to be nonempty.
		if (name is [0x30, 0x00])
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
	/// <exception cref="InvalidOperationException"><see cref="Extensions" /> holds <see langword="null" />, two extensions with one identifier or a key usage extension that does not decode as <see cref="Certificate.KeyUsage" /> requires, or <paramref name="key" /> does not hold the private key.</exception>
	/// <exception cref="CryptographicException">The key store or device that holds the private key failed to sign.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="key" /> has been disposed.</exception>
	public Certificate CreateSelfSigned(ISignatureKey key, SignatureAlgorithm algorithm, DateTimeOffset notBefore, DateTimeOffset notAfter)
	{
		ArgumentNullException.ThrowIfNull(key);

		if (!key.Supports(algorithm))
		{
			throw new ArgumentException("The key does not support the signature algorithm.", nameof(algorithm));
		}

		AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.FromSignatureAlgorithm(algorithm);
		notBefore = X509Time.TruncateToSeconds(notBefore);
		notAfter = X509Time.TruncateToSeconds(notAfter);

		if (notAfter < notBefore)
		{
			throw new ArgumentException("The end of the validity period is earlier than its start.", nameof(notAfter));
		}

		CertificateExtension[] extensions = [.. Extensions];

		foreach (CertificateExtension? extension in extensions)
		{
			if (extension is null)
			{
				throw new InvalidOperationException("The extensions include null.");
			}
		}

		// Decoding the certificate checks the extensions, so they are checked before signing.
		try
		{
			Certificate.CheckExtensions(extensions);
		}
		catch (AsnContentException e)
		{
			throw new InvalidOperationException(e.Message, e);
		}

		byte[] subjectPublicKeyInfo = new byte[key.SubjectPublicKeyInfoLength];
		key.ExportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		SubjectPublicKeyInfo.Decode(subjectPublicKeyInfo, nameof(key));

		byte[] tbsCertificate = WriteTbsCertificate(signatureAlgorithm, notBefore, notAfter, subjectPublicKeyInfo, extensions);
		byte[] signature = new byte[key.GetMaxSignatureLength(algorithm)];
		int signatureLength = key.Sign(algorithm, tbsCertificate, signature);

		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(tbsCertificate);
			writer.WriteEncodedValue(signatureAlgorithm.Encoded.Span);
			writer.WriteBitString(signature.AsSpan(0, signatureLength));
		}

		return Certificate.Decode(writer.Encode(), nameof(key));
	}

	private byte[] WriteTbsCertificate(AlgorithmIdentifier signatureAlgorithm, DateTimeOffset notBefore, DateTimeOffset notAfter, byte[] subjectPublicKeyInfo, CertificateExtension[] extensions)
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
			writer.WriteEncodedValue(SubjectName.Span);

			using (writer.PushSequence())
			{
				X509Time.Write(writer, notBefore);
				X509Time.Write(writer, notAfter);
			}

			writer.WriteEncodedValue(SubjectName.Span);
			writer.WriteEncodedValue(subjectPublicKeyInfo);

			if (extensions.Length > 0)
			{
				using (writer.PushSequence(Certificate.ExtensionsTag))
				using (writer.PushSequence())
				{
					foreach (CertificateExtension extension in extensions)
					{
						extension.Write(writer);
					}
				}
			}
		}

		return writer.Encode();
	}

	// 126 random bits in 16 bytes whose first is in [0x40, 0x7F], so the INTEGER takes 16 bytes with no zero byte for the sign.
	private static byte[] CreateSerialNumber()
	{
		byte[] serialNumber = new byte[RandomSerialNumberLength];
		RandomNumberGenerator.Fill(serialNumber);
		serialNumber[0] = (byte)(0x40 | serialNumber[0] & 0x3F);
		return serialNumber;
	}
}
