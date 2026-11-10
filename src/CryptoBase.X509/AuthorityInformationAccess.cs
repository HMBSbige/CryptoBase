using System.Text;

namespace CryptoBase.X509;

/// <summary>
/// Represents the value of an authority information access extension (RFC 5280, Sec. 4.2.2.1), which locates the certificates of the issuer and its OCSP responders.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class AuthorityInformationAccess
{
	internal const string OcspAccessMethod = "1.3.6.1.5.5.7.48.1";
	internal const string CAIssuersAccessMethod = "1.3.6.1.5.5.7.48.2";

	private AuthorityInformationAccess(AccessDescription[] descriptions)
	{
		Descriptions = descriptions;
		List<string> ocsp = [];
		List<string> caIssuers = [];

		foreach (AccessDescription description in descriptions)
		{
			if (description.Location.Type is not GeneralNameType.UniformResourceIdentifier)
			{
				continue;
			}

			switch (description.Method)
			{
				case OcspAccessMethod:
				{
					ocsp.Add(Encoding.ASCII.GetString(description.Location.Value.Span));
					break;
				}
				case CAIssuersAccessMethod:
				{
					caIssuers.Add(Encoding.ASCII.GetString(description.Location.Value.Span));
					break;
				}
			}
		}

		OcspUris = ocsp.AsReadOnly();
		CAIssuersUris = caIssuers.AsReadOnly();
	}

	/// <summary>
	/// Gets the URIs of the id-ad-ocsp access descriptions, in the order of the encoding, as they are encoded and of any scheme; empty if there are none.
	/// </summary>
	public IReadOnlyList<string> OcspUris { get; }

	/// <summary>
	/// Gets the URIs of the id-ad-caIssuers access descriptions, in the order of the encoding, as they are encoded and of any scheme; empty if there are none.
	/// </summary>
	public IReadOnlyList<string> CAIssuersUris { get; }

	internal IReadOnlyList<AccessDescription> Descriptions { get; }

	// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription.
	internal static AuthorityInformationAccess Read(ReadOnlyMemory<byte> value)
	{
		return new AuthorityInformationAccess([.. DerReader.ReadSoleSequenceOf(value, AccessDescription.Read)]);
	}
}

internal readonly record struct AccessDescription(string Method, GeneralName Location)
{
	// AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }.
	public static AccessDescription Read(ref DerReader reader)
	{
		DerReader description = reader.ReadSequence();
		string method = description.ReadObjectIdentifier();
		GeneralName location = GeneralName.ReadWithAddress(ref description);
		description.ThrowIfNotEmpty();
		return new AccessDescription(method, location);
	}
}
