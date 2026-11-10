using System.Text;

namespace CryptoBase.X509;

/// <summary>
/// Represents a DistributionPointName (RFC 5280, Sec. 4.2.1.13): the names of a CRL distribution point, as general names or as a name relative to the CRL issuer.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class DistributionPointName
{
	private static readonly Asn1Tag DistributionPointTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag FullNameTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag RelativeNameTag = new(TagClass.ContextSpecific, 1, true);

	private DistributionPointName(GeneralName[]? fullName, ReadOnlyMemory<byte>? nameRelativeToCrlIssuer)
	{
		FullName = fullName;
		NameRelativeToCrlIssuer = nameRelativeToCrlIssuer;
		Uris = fullName is null ? [] : Array.AsReadOnly(GetUris(fullName));
	}

	/// <summary>
	/// Gets the uniformResourceIdentifier entries of fullName, in the order of the encoding, as they are encoded; empty if there are none.
	/// </summary>
	/// <remarks>The entries are of any scheme, and <see cref="NameRelativeToCrlIssuer" /> has none.</remarks>
	public IReadOnlyList<string> Uris { get; }

	/// <summary>
	/// Gets the AttributeTypeAndValue elements of nameRelativeToCRLIssuer, the contents of its RelativeDistinguishedName, or <see langword="null" /> if the name is a fullName.
	/// </summary>
	public ReadOnlyMemory<byte>? NameRelativeToCrlIssuer { get; }

	// fullName, or null if the name is a nameRelativeToCRLIssuer.
	internal IReadOnlyList<GeneralName>? FullName { get; }

	// The names as RFC 5280, Sec. 6.3.3 (b)(2)(i), compares them: those of fullName, or the Name of a nameRelativeToCRLIssuer, a fragment appended to the DER of the base Name (Sec. 4.2.1.13).
	internal IReadOnlyList<GeneralName> GetNames(ReadOnlyMemory<byte> baseName)
	{
		if (FullName is { } names)
		{
			return names;
		}

		Debug.Assert(NameRelativeToCrlIssuer is not null);
		return [new GeneralName(GeneralNameType.DirectoryName, AppendRelativeName(baseName, NameRelativeToCrlIssuer.Value))];
	}

	// distributionPoint [0] DistributionPointName OPTIONAL, the first field of a DistributionPoint and of an IssuingDistributionPoint, or null if it is absent.
	// The implicit tag leaves it explicit as DistributionPointName is a CHOICE: fullName [0] GeneralNames or nameRelativeToCRLIssuer [1] RelativeDistinguishedName, both with implicit tags.
	internal static DistributionPointName? ReadOptional(ref DerReader reader)
	{
		if (!reader.TryReadSequence(DistributionPointTag, out DerReader wrapper))
		{
			return null;
		}

		DistributionPointName name;

		if (wrapper.PeekTagIs(FullNameTag))
		{
			name = new DistributionPointName(GeneralName.ReadGeneralNames(ref wrapper, FullNameTag), null);
		}
		else
		{
			DerReader relativeName = wrapper.ReadSetOf(RelativeNameTag);
			name = new DistributionPointName(null, ReadRelativeName(relativeName));
		}

		wrapper.ThrowIfNotEmpty();
		return name;
	}

	private static string[] GetUris(GeneralName[] names)
	{
		int count = 0;

		foreach (GeneralName name in names)
		{
			if (name.Type is GeneralNameType.UniformResourceIdentifier)
			{
				++count;
			}
		}

		string[] uris = count is 0 ? [] : new string[count];
		count = 0;

		foreach (GeneralName name in names)
		{
			if (name.Type is GeneralNameType.UniformResourceIdentifier)
			{
				uris[count++] = Encoding.ASCII.GetString(name.Value.Span);
			}
		}

		return uris;
	}

	// The contents of a nonempty SET OF AttributeTypeAndValue (RFC 5280, Sec. 4.1.2.4), whose values are single DER elements.
	private static ReadOnlyMemory<byte> ReadRelativeName(DerReader relativeName)
	{
		ReadOnlyMemory<byte> contents = relativeName.GetRemaining();
		relativeName.ThrowIfEmpty();

		while (relativeName.HasData)
		{
			DerReader attribute = relativeName.ReadSequence();
			attribute.SkipObjectIdentifier();
			attribute.ReadEncodedValue();
			attribute.ThrowIfNotEmpty();
		}

		return contents;
	}

	private static ReadOnlyMemory<byte> AppendRelativeName(ReadOnlyMemory<byte> baseName, ReadOnlyMemory<byte> relativeName)
	{
		AsnDecoder.ReadSequence(baseName.Span, AsnEncodingRules.DER, out int offset, out int length, out _);
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			WriteElements(writer, baseName.Slice(offset, length));

			using (writer.PushSetOf())
			{
				WriteElements(writer, relativeName);
			}
		}

		return writer.Encode();
	}

	private static void WriteElements(AsnWriter writer, ReadOnlyMemory<byte> elements)
	{
		DerReader reader = new(elements);

		while (reader.HasData)
		{
			writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
		}
	}
}
