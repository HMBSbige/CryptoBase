using System.Runtime.InteropServices;
using System.Text;

namespace CryptoBase.X509;

// The value of a certificate policies extension (RFC 5280, Sec. 4.2.1.4): certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation, without the qualifiers, which path validation does not use.
// Policies are the contents of the OBJECT IDENTIFIERs other than anyPolicy, slices of the extension's memory; each appears once, as the section requires. The instance is immutable.
internal sealed class CertificatePolicies(ReadOnlyMemory<byte>[] policies, bool hasAnyPolicy, bool hasUnrecognizedQualifier)
{
	private const int MaxDirectlyCompared = 8;

	// The tags of the primitive string types that a qualifier can hold; DER does not allow the constructed forms.
	private const byte Utf8StringTag = 0x0C;
	private const byte IA5StringTag = 0x16;
	private const byte VisibleStringTag = 0x1A;
	private const byte BmpStringTag = 0x1E;

	// The contents of the OBJECT IDENTIFIERs id-qt-cps and id-qt-unotice, the qualifiers of RFC 5280, Sec. 4.2.1.4, neither of which changes the outcome of path validation.
	private static ReadOnlySpan<byte> CpsQualifier => [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01];

	private static ReadOnlySpan<byte> UserNoticeQualifier => [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02];

	public ReadOnlyMemory<byte>[] Policies { get; } = policies;

	public bool HasAnyPolicy { get; } = hasAnyPolicy;

	// Whether a qualifier is neither of the above or has a value that does not decode as the type that the section gives it; Sec. 4.2.1.4 requires a validator to interpret those of a critical extension or to reject the certificate.
	public bool HasUnrecognizedQualifier { get; } = hasUnrecognizedQualifier;

	// PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId, policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }.
	public static CertificatePolicies Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		sequence.ThrowIfEmpty();
		List<ReadOnlyMemory<byte>> policies = [];
		bool hasAnyPolicy = false;
		bool hasUnrecognizedQualifier = false;
		HashSet<ReadOnlyMemory<byte>>? seen = null;

		while (sequence.HasData)
		{
			DerReader information = sequence.ReadSequence();
			ReadOnlyMemory<byte> policy = information.ReadObjectIdentifierContents();

			if (information.HasData)
			{
				DerReader qualifiers = information.ReadSequence();
				qualifiers.ThrowIfEmpty();
				information.ThrowIfNotEmpty();

				while (qualifiers.HasData)
				{
					// PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }.
					DerReader qualifier = qualifiers.ReadSequence();
					ReadOnlySpan<byte> identifier = qualifier.ReadObjectIdentifierContents().Span;
					ReadOnlyMemory<byte> qualifierValue = qualifier.ReadEncodedValue();
					qualifier.ThrowIfNotEmpty();
					hasUnrecognizedQualifier |= !IsInterpreted(identifier, qualifierValue);
				}
			}

			// anyPolicy is not in the list; each is compared with the policies before it.
			bool isAnyPolicy = PolicyGraph.IsAnyPolicy(policy);

			if (isAnyPolicy ? hasAnyPolicy : IsRepeated(policies, ref seen, policy))
			{
				throw new AsnContentException("A certificate policy appears twice.");
			}

			if (isAnyPolicy)
			{
				hasAnyPolicy = true;
			}
			else
			{
				policies.Add(policy);
			}
		}

		return new CertificatePolicies([.. policies], hasAnyPolicy, hasUnrecognizedQualifier);
	}

	// Whether value, read whole, decodes as the type that Sec. 4.2.1.4 gives the qualifier, CPSuri ::= IA5String or UserNotice, which the validator then interprets; neither changes the outcome, so the text is not kept.
	private static bool IsInterpreted(ReadOnlySpan<byte> identifier, ReadOnlyMemory<byte> value)
	{
		if (identifier.SequenceEqual(CpsQualifier))
		{
			ReadOnlySpan<byte> element = value.Span;

			if (element[0] is not IA5StringTag)
			{
				return false;
			}

			AsnDecoder.ReadEncodedValue(element, AsnEncodingRules.DER, out int offset, out int length, out _);
			return Ascii.IsValid(element.Slice(offset, length));
		}

		if (!identifier.SequenceEqual(UserNoticeQualifier))
		{
			return false;
		}

		try
		{
			ReadUserNotice(value);
			return true;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// UserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL, explicitText DisplayText OPTIONAL }, and NoticeReference ::= SEQUENCE { organization DisplayText, noticeNumbers SEQUENCE OF INTEGER }.
	private static void ReadUserNotice(ReadOnlyMemory<byte> value)
	{
		DerReader notice = DerReader.ReadSoleSequence(value);

		if (notice.PeekTagIs(Asn1Tag.Sequence))
		{
			DerReader reference = notice.ReadSequence();
			ReadDisplayText(ref reference);
			DerReader numbers = reference.ReadSequence();
			reference.ThrowIfNotEmpty();

			while (numbers.HasData)
			{
				numbers.ReadIntegerBytes();
			}
		}

		if (notice.HasData)
		{
			ReadDisplayText(ref notice);
		}

		notice.ThrowIfNotEmpty();
	}

	// DisplayText ::= CHOICE { ia5String IA5String, visibleString VisibleString, bmpString BMPString, utf8String UTF8String }. The SIZE (1..200) of each is not checked: Sec. 4.2.1.4 asks users to handle the longer texts that some CAs issue.
	private static void ReadDisplayText(ref DerReader reader)
	{
		ReadOnlySpan<byte> element = reader.ReadEncodedValue().Span;

		UniversalTagNumber type = element[0] switch
		{
			IA5StringTag => UniversalTagNumber.IA5String,
			VisibleStringTag => UniversalTagNumber.VisibleString,
			BmpStringTag => UniversalTagNumber.BMPString,
			Utf8StringTag => UniversalTagNumber.UTF8String,
			_ => throw new AsnContentException("A DisplayText is not one of its string types.")
		};

		AsnDecoder.ReadCharacterString(element, AsnEncodingRules.DER, type, out _);
	}

	// Comparing directly costs less than a set for the few policies that an extension has; the set keeps the work linear for a long list.
	private static bool IsRepeated(List<ReadOnlyMemory<byte>> policies, ref HashSet<ReadOnlyMemory<byte>>? seen, ReadOnlyMemory<byte> policy)
	{
		if (seen is null && policies.Count < MaxDirectlyCompared)
		{
			foreach (ReadOnlyMemory<byte> earlier in CollectionsMarshal.AsSpan(policies))
			{
				if (earlier.Span.SequenceEqual(policy.Span))
				{
					return true;
				}
			}

			return false;
		}

		seen ??= new HashSet<ReadOnlyMemory<byte>>(policies, ByteMemoryComparer.Instance);
		return !seen.Add(policy);
	}
}

// The value of a policy mappings extension (RFC 5280, Sec. 4.2.1.5): SEQUENCE SIZE (1..MAX) OF SEQUENCE { issuerDomainPolicy CertPolicyId, subjectDomainPolicy CertPolicyId }, the pairs as slices of the extension's memory. Neither may be anyPolicy.
internal sealed class PolicyMappings((ReadOnlyMemory<byte> IssuerDomainPolicy, ReadOnlyMemory<byte> SubjectDomainPolicy)[] mappings)
{
	public (ReadOnlyMemory<byte> IssuerDomainPolicy, ReadOnlyMemory<byte> SubjectDomainPolicy)[] Mappings { get; } = mappings;

	public static PolicyMappings Read(ReadOnlyMemory<byte> value)
	{
		return new PolicyMappings([.. DerReader.ReadSoleSequenceOf(value, ReadMapping)]);
	}

	private static (ReadOnlyMemory<byte> IssuerDomainPolicy, ReadOnlyMemory<byte> SubjectDomainPolicy) ReadMapping(ref DerReader reader)
	{
		DerReader mapping = reader.ReadSequence();
		ReadOnlyMemory<byte> issuerDomainPolicy = mapping.ReadObjectIdentifierContents();
		ReadOnlyMemory<byte> subjectDomainPolicy = mapping.ReadObjectIdentifierContents();
		mapping.ThrowIfNotEmpty();

		if (PolicyGraph.IsAnyPolicy(issuerDomainPolicy) || PolicyGraph.IsAnyPolicy(subjectDomainPolicy))
		{
			throw new AsnContentException("A policy mapping names anyPolicy.");
		}

		return (issuerDomainPolicy, subjectDomainPolicy);
	}
}

// The value of a policy constraints extension (RFC 5280, Sec. 4.2.1.11): PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] SkipCerts OPTIONAL, inhibitPolicyMapping [1] SkipCerts OPTIONAL }, with implicit tags and one field at least, as the section requires of CAs.
internal sealed class PolicyConstraints(int? requireExplicitPolicy, int? inhibitPolicyMapping)
{
	private static readonly Asn1Tag RequireExplicitPolicyTag = new(TagClass.ContextSpecific, 0);
	private static readonly Asn1Tag InhibitPolicyMappingTag = new(TagClass.ContextSpecific, 1);

	public int? RequireExplicitPolicy { get; } = requireExplicitPolicy;

	public int? InhibitPolicyMapping { get; } = inhibitPolicyMapping;

	public static PolicyConstraints Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		int? requireExplicitPolicy = sequence.PeekTagIs(RequireExplicitPolicyTag) ? ReadSkipCerts(ref sequence, RequireExplicitPolicyTag) : null;
		int? inhibitPolicyMapping = sequence.PeekTagIs(InhibitPolicyMappingTag) ? ReadSkipCerts(ref sequence, InhibitPolicyMappingTag) : null;
		sequence.ThrowIfNotEmpty();

		if (requireExplicitPolicy is null && inhibitPolicyMapping is null)
		{
			throw new AsnContentException("The policy constraints have neither field.");
		}

		return new PolicyConstraints(requireExplicitPolicy, inhibitPolicyMapping);
	}

	// InhibitAnyPolicy ::= SkipCerts (RFC 5280, Sec. 4.2.1.14).
	public static int ReadInhibitAnyPolicy(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		int skipCerts = ReadSkipCerts(ref reader);
		reader.ThrowIfNotEmpty();
		return skipCerts;
	}

	// SkipCerts ::= INTEGER (0..MAX).
	private static int ReadSkipCerts(ref DerReader reader, Asn1Tag? tag = null)
	{
		return reader.ReadSaturatedInt32("A SkipCerts value is negative.", tag);
	}
}
