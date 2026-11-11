using System.Text;

namespace CryptoBase.X509;

/// <summary>
/// Represents a DistributionPointName (RFC 5280, Sec. 4.2.1.13): the names of a CRL distribution point, as general names, a <see cref="FullName" />, or as a name relative to the CRL issuer, a <see cref="RelativeToCrlIssuer" />.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public closed class DistributionPointName
{
	private static readonly Asn1Tag DistributionPointTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag FullNameTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag RelativeNameTag = new(TagClass.ContextSpecific, 1, true);

	/// <summary>
	/// Gets the uniformResourceIdentifier entries of fullName, in the order of the encoding, as they are encoded; empty if there are none.
	/// </summary>
	/// <remarks>The entries are of any scheme, and a <see cref="RelativeToCrlIssuer" /> has none.</remarks>
	public abstract IReadOnlyList<string> Uris { get; }

	// The names as RFC 5280, Sec. 6.3.3 (b)(2)(i), compares them: those of fullName, or the Name of a nameRelativeToCRLIssuer, a fragment appended to the DER of the base Name (Sec. 4.2.1.13).
	internal abstract IReadOnlyList<GeneralName> GetNames(ReadOnlyMemory<byte> baseName);

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
			name = new FullName(GeneralName.ReadGeneralNames(ref wrapper, FullNameTag));
		}
		else
		{
			DerReader relativeName = wrapper.ReadSetOf(RelativeNameTag);
			name = new RelativeToCrlIssuer(ReadRelativeName(relativeName));
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

	/// <summary>
	/// Represents a fullName: the general names of the distribution point.
	/// </summary>
	public sealed class FullName : DistributionPointName
	{
		internal FullName(GeneralName[] names)
		{
			Names = names;
			Uris = Array.AsReadOnly(GetUris(names));
		}

		/// <inheritdoc />
		public override IReadOnlyList<string> Uris { get; }

		internal IReadOnlyList<GeneralName> Names { get; }

		internal override IReadOnlyList<GeneralName> GetNames(ReadOnlyMemory<byte> baseName)
		{
			return Names;
		}
	}

	/// <summary>
	/// Represents a nameRelativeToCRLIssuer: a name relative to that of the CRL issuer.
	/// </summary>
	public sealed class RelativeToCrlIssuer : DistributionPointName
	{
		internal RelativeToCrlIssuer(ReadOnlyMemory<byte> relativeName)
		{
			RelativeName = relativeName;
		}

		/// <summary>
		/// Gets the AttributeTypeAndValue elements of nameRelativeToCRLIssuer, the contents of its RelativeDistinguishedName.
		/// </summary>
		public ReadOnlyMemory<byte> RelativeName { get; }

		/// <inheritdoc />
		public override IReadOnlyList<string> Uris => [];

		internal override IReadOnlyList<GeneralName> GetNames(ReadOnlyMemory<byte> baseName)
		{
			return [new GeneralName(GeneralNameType.DirectoryName, AppendRelativeName(baseName, RelativeName))];
		}
	}
}
