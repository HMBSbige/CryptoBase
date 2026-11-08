using System.Globalization;

namespace CryptoBase.X509;

/// <summary>
/// Represents a certificate extension (RFC 5280, Sec. 4.1.2.9): its identifier, its criticality and its value.
/// </summary>
public sealed class CertificateExtension
{
	private static readonly string?[] IdCeIdentifiers = new string?[128];

	/// <summary>
	/// Initializes an extension.
	/// </summary>
	/// <param name="oid">The extension identifier, as a dotted-decimal object identifier.</param>
	/// <param name="critical"><see langword="true" /> if a certificate user that does not recognize the extension must reject the certificate; otherwise, <see langword="false" />.</param>
	/// <param name="value">The contents of extnValue, usually the DER encoding of the extension's ASN.1 type; the instance holds a copy.</param>
	/// <exception cref="ArgumentNullException"><paramref name="oid" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="oid" /> is not a valid object identifier.</exception>
	public CertificateExtension(string oid, bool critical, ReadOnlySpan<byte> value)
	{
		ArgumentNullException.ThrowIfNull(oid);

		try
		{
			new AsnWriter(AsnEncodingRules.DER).WriteObjectIdentifier(oid);
		}
		catch (ArgumentException e)
		{
			throw new ArgumentException("The object identifier is invalid.", nameof(oid), e);
		}

		Oid = oid;
		Critical = critical;
		Value = value.ToArray();
	}

	private CertificateExtension(string oid, bool critical, ReadOnlyMemory<byte> value)
	{
		Oid = oid;
		Critical = critical;
		Value = value;
	}

	/// <summary>
	/// Gets the extension identifier as a dotted-decimal object identifier.
	/// </summary>
	public string Oid { get; }

	/// <summary>
	/// Gets a value that indicates whether a certificate user that does not recognize the extension must reject the certificate.
	/// </summary>
	public bool Critical { get; }

	/// <summary>
	/// Gets the contents of extnValue.
	/// </summary>
	public ReadOnlyMemory<byte> Value { get; }

	// Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }; DER omits critical when it is FALSE. The value is a slice of the reader's memory.
	internal static CertificateExtension Read(ref DerReader reader)
	{
		DerReader contents = reader.ReadSequence();
		string oid = ReadIdentifier(ref contents);
		bool critical = contents.PeekTagIs(Asn1Tag.Boolean);

		if (critical && !contents.ReadBoolean())
		{
			throw new AsnContentException();
		}

		ReadOnlyMemory<byte> value = contents.ReadOctetString();
		contents.ThrowIfNotEmpty();
		return new CertificateExtension(oid, critical, value);
	}

	// Nearly all extensions are under id-ce (2.5.29), so their identifiers have one string each, kept as they are first read. Threads that race write equal strings.
	private static string ReadIdentifier(ref DerReader reader)
	{
		if (reader.GetRemaining().Span is [0x06, 0x03, 0x55, 0x1D, var last and < 0x80, ..])
		{
			reader.ReadEncodedValue();
			return IdCeIdentifiers[last] ??= string.Create(CultureInfo.InvariantCulture, $"2.5.29.{last}");
		}

		return reader.ReadObjectIdentifier();
	}

	// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension under an explicit tag, each extnID at most once, as a CRL and an OCSP response hold them. The values are slices of the reader's memory.
	internal static IReadOnlyList<CertificateExtension> ReadList(ref DerReader reader, Asn1Tag tag)
	{
		DerReader wrapper = reader.ReadSequence(tag);
		DerReader sequence = wrapper.ReadSequence();
		wrapper.ThrowIfNotEmpty();
		sequence.ThrowIfEmpty();
		List<CertificateExtension> extensions = [];
		HashSet<string> oids = new(StringComparer.Ordinal);

		while (sequence.HasData)
		{
			CertificateExtension extension = Read(ref sequence);

			if (!oids.Add(extension.Oid))
			{
				throw new AsnContentException($"The extensions include {extension.Oid} more than once.");
			}

			extensions.Add(extension);
		}

		return extensions.AsReadOnly();
	}

	internal void Write(AsnWriter writer)
	{
		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier(Oid);

			if (Critical)
			{
				writer.WriteBoolean(true);
			}

			writer.WriteOctetString(Value.Span);
		}
	}
}
