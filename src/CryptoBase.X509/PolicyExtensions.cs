using System.Runtime.InteropServices;

namespace CryptoBase.X509;

// The value of a certificate policies extension (RFC 5280, Sec. 4.2.1.4): certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation, without the qualifiers, which path validation does not use.
// Policies are the contents of the OBJECT IDENTIFIERs other than anyPolicy, slices of the extension's memory; each appears once, as the section requires. The instance is immutable.
internal sealed class CertificatePolicies
{
	private const int MaxDirectlyCompared = 8;

	// The contents of the OBJECT IDENTIFIERs id-qt-cps and id-qt-unotice, the qualifiers of RFC 5280, Sec. 4.2.1.4, neither of which changes the outcome of path validation.
	private static ReadOnlySpan<byte> CpsQualifier => [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01];

	private static ReadOnlySpan<byte> UserNoticeQualifier => [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02];

	private CertificatePolicies(ReadOnlyMemory<byte>[] policies, bool hasAnyPolicy, bool hasUnrecognizedQualifier)
	{
		Policies = policies;
		HasAnyPolicy = hasAnyPolicy;
		HasUnrecognizedQualifier = hasUnrecognizedQualifier;
	}

	public ReadOnlyMemory<byte>[] Policies { get; }

	public bool HasAnyPolicy { get; }

	// Whether a qualifier is neither of the above; Sec. 4.2.1.4 requires a validator to interpret those of a critical extension or to reject the certificate.
	public bool HasUnrecognizedQualifier { get; }

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
					qualifier.ReadEncodedValue();
					qualifier.ThrowIfNotEmpty();
					hasUnrecognizedQualifier |= !identifier.SequenceEqual(CpsQualifier) && !identifier.SequenceEqual(UserNoticeQualifier);
				}
			}

			// anyPolicy is not in the list; each is compared with the policies before it.
			bool isAnyPolicy = policy.Span.SequenceEqual(PolicyGraph.AnyPolicy.Span);

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
internal sealed class PolicyMappings
{
	private PolicyMappings((ReadOnlyMemory<byte> IssuerDomainPolicy, ReadOnlyMemory<byte> SubjectDomainPolicy)[] mappings)
	{
		Mappings = mappings;
	}

	public (ReadOnlyMemory<byte> IssuerDomainPolicy, ReadOnlyMemory<byte> SubjectDomainPolicy)[] Mappings { get; }

	public static PolicyMappings Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		sequence.ThrowIfEmpty();
		List<(ReadOnlyMemory<byte>, ReadOnlyMemory<byte>)> mappings = [];

		while (sequence.HasData)
		{
			DerReader mapping = sequence.ReadSequence();
			ReadOnlyMemory<byte> issuerDomainPolicy = mapping.ReadObjectIdentifierContents();
			ReadOnlyMemory<byte> subjectDomainPolicy = mapping.ReadObjectIdentifierContents();
			mapping.ThrowIfNotEmpty();

			if (issuerDomainPolicy.Span.SequenceEqual(PolicyGraph.AnyPolicy.Span) || subjectDomainPolicy.Span.SequenceEqual(PolicyGraph.AnyPolicy.Span))
			{
				throw new AsnContentException("A policy mapping names anyPolicy.");
			}

			mappings.Add((issuerDomainPolicy, subjectDomainPolicy));
		}

		return new PolicyMappings([.. mappings]);
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
		int? requireExplicitPolicy = null;
		int? inhibitPolicyMapping = null;

		if (sequence.PeekTagIs(RequireExplicitPolicyTag))
		{
			requireExplicitPolicy = ReadSkipCerts(ref sequence, RequireExplicitPolicyTag);
		}

		if (sequence.PeekTagIs(InhibitPolicyMappingTag))
		{
			inhibitPolicyMapping = ReadSkipCerts(ref sequence, InhibitPolicyMappingTag);
		}

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
