using System.Text;

namespace CryptoBase.X509;

// A GeneralName of RFC 5280, Sec. 4.2.1.6. Value is a slice of the reader's memory: the characters of an IA5String, the octets of an iPAddress, the contents of the OBJECT IDENTIFIER of a registeredID, the DER of the Name of a directoryName, and the contents of the SEQUENCE of the others.
internal readonly record struct GeneralName(GeneralNameType Type, ReadOnlyMemory<byte> Value)
{
	private static readonly Asn1Tag ExplicitTag0 = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag ExplicitTag1 = new(TagClass.ContextSpecific, 1, true);

	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName, under tag if it is implicitly tagged, each as ReadWithAddress reads it.
	public static GeneralName[] ReadGeneralNames(ref DerReader reader, Asn1Tag? tag = null)
	{
		DerReader sequence = reader.ReadSequence(tag);
		sequence.ThrowIfEmpty();
		List<GeneralName> names = [];

		while (sequence.HasData)
		{
			names.Add(ReadWithAddress(ref sequence));
		}

		return [.. names];
	}

	// A GeneralName outside name constraints, where an iPAddress holds an IPv4 or IPv6 address, so it has 4 or 16 octets.
	public static GeneralName ReadWithAddress(ref DerReader reader)
	{
		GeneralName name = Read(ref reader);

		if (name is { Type: GeneralNameType.IPAddress, Value.Length: not (4 or 16) })
		{
			throw new AsnContentException("An iPAddress has neither 4 nor 16 octets.");
		}

		return name;
	}

	// The implicit tags of RFC 5280 leave the IA5String, OCTET STRING and OBJECT IDENTIFIER alternatives primitive, and the SEQUENCE ones constructed; directoryName is explicit, as Name is a CHOICE. The values in an otherName and an ediPartyName need only be single DER elements, and the components of an x400Address DER elements.
	public static GeneralName Read(ref DerReader reader)
	{
		ReadOnlyMemory<byte> element = reader.ReadEncodedValue();
		Asn1Tag tag = Asn1Tag.Decode(element.Span, out _);

		if (tag.TagClass is not TagClass.ContextSpecific || tag.TagValue > (int)GeneralNameType.RegisteredId)
		{
			throw new AsnContentException("A GeneralName has an unknown tag.");
		}

		GeneralNameType type = (GeneralNameType)tag.TagValue;
		bool constructed = type is GeneralNameType.OtherName or GeneralNameType.X400Address or GeneralNameType.DirectoryName or GeneralNameType.EdiPartyName;

		if (tag.IsConstructed != constructed)
		{
			throw new AsnContentException();
		}

		AsnDecoder.ReadEncodedValue(element.Span, AsnEncodingRules.DER, out int offset, out int length, out _);
		ReadOnlyMemory<byte> contents = element.Slice(offset, length);

		switch (type)
		{
			case GeneralNameType.Rfc822Name or GeneralNameType.DnsName or GeneralNameType.UniformResourceIdentifier when !Ascii.IsValid(contents.Span):
			{
				throw new AsnContentException("An IA5String holds a byte above 0x7F.");
			}
			case GeneralNameType.RegisteredId:
			{
				AsnDecoder.ReadObjectIdentifier(element.Span, AsnEncodingRules.DER, out _, tag);
				break;
			}
			case GeneralNameType.OtherName:
			{
				// OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }.
				DerReader otherName = new(contents);
				otherName.SkipObjectIdentifier();
				otherName.ReadExplicit(ExplicitTag0);
				otherName.ThrowIfNotEmpty();
				break;
			}
			case GeneralNameType.X400Address:
			{
				// ORAddress ::= SEQUENCE { built-in-standard-attributes BuiltInStandardAttributes, built-in-domain-defined-attributes BuiltInDomainDefinedAttributes OPTIONAL, extension-attributes ExtensionAttributes OPTIONAL } (RFC 5280, Appendix A.1), of which the first is required.
				DerReader address = new(contents);
				address.ThrowIfEmpty();

				while (address.HasData)
				{
					address.ReadEncodedValue();
				}

				break;
			}
			case GeneralNameType.DirectoryName:
			{
				DerReader directoryName = new(contents);
				contents = X509Name.Read(ref directoryName);
				directoryName.ThrowIfNotEmpty();
				break;
			}
			case GeneralNameType.EdiPartyName:
			{
				// EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1] DirectoryString }, explicit as DirectoryString is a CHOICE.
				DerReader ediPartyName = new(contents);

				ediPartyName.TryReadExplicit(ExplicitTag0, out _);
				ediPartyName.ReadExplicit(ExplicitTag1);
				ediPartyName.ThrowIfNotEmpty();
				break;
			}
		}

		return new GeneralName(type, contents);
	}
}
