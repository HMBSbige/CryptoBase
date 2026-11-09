using System.Runtime.CompilerServices;

namespace CryptoBase.X509;

// The extensions that Certificate decodes on first use rather than when it decodes the certificate, so that an error in one appears only to the caller that asks for it. The values are slices of the certificate's memory, and the instance is immutable to its users.
// The authority information access and CRL distribution points extensions are decoded when they are first read, for the validations that retrieve or check revocation; the others are all read by every validation.
internal sealed class DecodedExtensions
{
	internal const string SubjectKeyIdentifierOid = "2.5.29.14";
	internal const string SubjectAlternativeNameOid = "2.5.29.17";
	internal const string BasicConstraintsOid = "2.5.29.19";
	internal const string NameConstraintsOid = "2.5.29.30";
	internal const string CertificatePoliciesOid = "2.5.29.32";
	internal const string PolicyMappingsOid = "2.5.29.33";
	internal const string AuthorityKeyIdentifierOid = "2.5.29.35";
	internal const string PolicyConstraintsOid = "2.5.29.36";
	internal const string ExtendedKeyUsageOid = "2.5.29.37";
	internal const string InhibitAnyPolicyOid = "2.5.29.54";
	private const string AuthorityInformationAccessOid = "1.3.6.1.5.5.7.1.1";
	internal const string CrlDistributionPointsOid = "2.5.29.31";
	private const string FreshestCrlOid = "2.5.29.46";
	private const string NoRevocationAvailableOid = "2.5.29.56";
	internal const string OcspNoCheckOid = "1.3.6.1.5.5.7.48.1.5";

	private readonly CertificateExtension? _authorityInformationAccess;
	private readonly CertificateExtension? _crlDistributionPoints;
	private readonly bool _hasFreshestCrl;

	private StrongBox<DecodedExtension<AuthorityInformationAccess>>? _decodedAuthorityInformationAccess;
	private StrongBox<DecodedExtension<IReadOnlyList<CrlDistributionPoint>>>? _decodedCrlDistributionPoints;

	// Certificate allows each extension once.
	public DecodedExtensions(IReadOnlyList<CertificateExtension> extensions)
	{
		// Indexed, as an enumerator of the interface would be allocated.
		for (int i = 0; i < extensions.Count; ++i)
		{
			CertificateExtension extension = extensions[i];

			switch (extension.Oid)
			{
				case AuthorityKeyIdentifierOid:
				{
					AuthorityKeyIdentifier = DecodedExtension<AuthorityKeyIdentifier>.Decode(extension.Value, X509.AuthorityKeyIdentifier.Read);
					break;
				}
				case SubjectKeyIdentifierOid:
				{
					SubjectKeyIdentifier = DecodedExtension<ReadOnlyMemory<byte>?>.Decode(extension.Value, static value => ReadSubjectKeyIdentifier(value));
					break;
				}
				case SubjectAlternativeNameOid:
				{
					SubjectAlternativeName = DecodedExtension<SubjectAlternativeName>.Decode(extension.Value, X509.SubjectAlternativeName.Read);
					break;
				}
				case BasicConstraintsOid:
				{
					BasicConstraints = DecodedExtension<BasicConstraints>.Decode(extension.Value, X509.BasicConstraints.Read);
					break;
				}
				case ExtendedKeyUsageOid:
				{
					ExtendedKeyUsage = DecodedExtension<ExtendedKeyUsage>.Decode(extension.Value, X509.ExtendedKeyUsage.Read);
					break;
				}
				case NameConstraintsOid:
				{
					NameConstraints = DecodedExtension<NameConstraints>.Decode(extension.Value, X509.NameConstraints.Read);
					break;
				}
				case CertificatePoliciesOid:
				{
					CertificatePolicies = DecodedExtension<CertificatePolicies>.Decode(extension.Value, X509.CertificatePolicies.Read);
					break;
				}
				case PolicyMappingsOid:
				{
					PolicyMappings = DecodedExtension<PolicyMappings>.Decode(extension.Value, X509.PolicyMappings.Read);
					break;
				}
				case PolicyConstraintsOid:
				{
					PolicyConstraints = DecodedExtension<PolicyConstraints>.Decode(extension.Value, X509.PolicyConstraints.Read);
					break;
				}
				case InhibitAnyPolicyOid:
				{
					InhibitAnyPolicy = DecodedExtension<int?>.Decode(extension.Value, static value => X509.PolicyConstraints.ReadInhibitAnyPolicy(value));
					break;
				}
				case AuthorityInformationAccessOid:
				{
					_authorityInformationAccess = extension;
					break;
				}
				case CrlDistributionPointsOid:
				{
					_crlDistributionPoints = extension;
					break;
				}
				case FreshestCrlOid:
				{
					_hasFreshestCrl = true;
					break;
				}
				case NoRevocationAvailableOid:
				{
					NoRevocationAvailable = DecodedExtension<bool>.Decode(extension.Value, ReadNull);
					break;
				}
				case OcspNoCheckOid:
				{
					OcspNoCheck = DecodedExtension<bool>.Decode(extension.Value, ReadNull);
					break;
				}
			}
		}
	}

	public DecodedExtension<AuthorityKeyIdentifier> AuthorityKeyIdentifier { get; }

	public DecodedExtension<ReadOnlyMemory<byte>?> SubjectKeyIdentifier { get; }

	public DecodedExtension<SubjectAlternativeName> SubjectAlternativeName { get; }

	public DecodedExtension<BasicConstraints> BasicConstraints { get; }

	public DecodedExtension<ExtendedKeyUsage> ExtendedKeyUsage { get; }

	public DecodedExtension<NameConstraints> NameConstraints { get; }

	public DecodedExtension<CertificatePolicies> CertificatePolicies { get; }

	public DecodedExtension<PolicyMappings> PolicyMappings { get; }

	public DecodedExtension<PolicyConstraints> PolicyConstraints { get; }

	public DecodedExtension<int?> InhibitAnyPolicy { get; }

	// True with the extension, if its value is NULL.
	public DecodedExtension<bool> NoRevocationAvailable { get; }

	// True with the extension, if its value is NULL.
	public DecodedExtension<bool> OcspNoCheck { get; }

	// RFC 9608, Sec. 4: the certificate has no revocation status to check. A value that is not NULL does not exempt it.
	public bool IsExemptFromRevocationCheck => NoRevocationAvailable.Value || OcspNoCheck.Value;

	public DecodedExtension<AuthorityInformationAccess> AuthorityInformationAccess => GetOrDecode(ref _decodedAuthorityInformationAccess, _authorityInformationAccess, X509.AuthorityInformationAccess.Read);

	public DecodedExtension<IReadOnlyList<CrlDistributionPoint>> CrlDistributionPoints => GetOrDecode(ref _decodedCrlDistributionPoints, _crlDistributionPoints, CrlDistributionPoint.ReadList);

	// RFC 9608, Sec. 3: how a certificate with the noRevAvail extension breaks the rules for it, which makes it invalid, as the end of a sentence about it; null if it does not, or has no such extension.
	public string? FindNoRevocationAvailableProblem()
	{
		if (!NoRevocationAvailable.Value)
		{
			return null;
		}

		if (BasicConstraints.Value is { CertificateAuthority: true })
		{
			return "has a noRevAvail extension, which a CA certificate must not have";
		}

		if (_crlDistributionPoints is not null)
		{
			return "has both a noRevAvail and a CRL distribution points extension, which RFC 9608 forbids";
		}

		if (_hasFreshestCrl)
		{
			return "has both a noRevAvail and a freshest CRL extension, which RFC 9608 forbids";
		}

		DecodedExtension<AuthorityInformationAccess> access = AuthorityInformationAccess;

		// An extension that does not decode may name a responder.
		if (access.Error is not null)
		{
			return "has a noRevAvail extension and an authority information access extension that does not decode";
		}

		foreach (AccessDescription description in access.Value?.Descriptions ?? [])
		{
			if (description.Method is X509.AuthorityInformationAccess.OcspAccessMethod)
			{
				return "has both a noRevAvail extension and an id-ad-ocsp access description, which RFC 9608 forbids";
			}
		}

		return null;
	}

	// Threads that race decode the extension alike, and all use the result stored first, so that later calls return the same instances.
	private static DecodedExtension<T> GetOrDecode<T>(ref StrongBox<DecodedExtension<T>>? slot, CertificateExtension? extension, Func<ReadOnlyMemory<byte>, T> read)
	{
		if (extension is null)
		{
			return default;
		}

		if (Volatile.Read(ref slot) is { } decoded)
		{
			return decoded.Value;
		}

		StrongBox<DecodedExtension<T>> created = new(DecodedExtension<T>.Decode(extension.Value, read));
		return (Interlocked.CompareExchange(ref slot, created, null) ?? created).Value;
	}

	// SubjectKeyIdentifier ::= KeyIdentifier, and KeyIdentifier ::= OCTET STRING (RFC 5280, Sec. 4.2.1.2).
	private static ReadOnlyMemory<byte> ReadSubjectKeyIdentifier(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		ReadOnlyMemory<byte> keyIdentifier = reader.ReadOctetString();
		reader.ThrowIfNotEmpty();
		return keyIdentifier;
	}

	// The value of the noRevAvail extension is NULL (RFC 9608, Sec. 2), as is that of the ocsp-nocheck extension (RFC 6960, Sec. 4.2.2.2.1).
	private static bool ReadNull(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		reader.ReadNull();
		reader.ThrowIfNotEmpty();
		return true;
	}
}
