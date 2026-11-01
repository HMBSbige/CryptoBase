using System.Text;

namespace CryptoBase.X509;

/// <summary>
/// Represents the value of a subject alternative name extension (RFC 5280, Sec. 4.2.1.6): the identities, such as DNS names and IP addresses, that a certificate binds to its subject.
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of every GeneralName, including the forms that this version does not expose: there must be at least one, each must be one of the nine alternatives of RFC 5280, an IA5String must hold only ASCII, an iPAddress must have 4 or 16 octets, a directoryName must be a Name, the values of an otherName and an ediPartyName must be single DER elements, and the contents of an x400Address are not checked.
/// The DNS names need not be valid to decode; <see cref="MatchesHostName" /> ignores those that are not.
/// </para>
/// <para>
/// An instance holds its own copy of the encoding, and the members return slices of it. Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class SubjectAlternativeName
{
	private readonly string[] _dnsNamePatterns;
	private readonly string[] _wildcardPatterns;

	// The list that IPAddresses wraps, which Matches enumerates without allocating.
	private readonly List<ReadOnlyMemory<byte>> _addresses;

	private SubjectAlternativeName(GeneralName[] names)
	{
		Names = names;
		List<string> dnsNames = [];
		List<ReadOnlyMemory<byte>> addresses = [];
		List<string> dnsNamePatterns = [];
		List<string> wildcardPatterns = [];

		foreach (GeneralName name in names)
		{
			if (name.Type is GeneralNameType.IPAddress)
			{
				addresses.Add(name.Value);
			}
			else if (name.Type is GeneralNameType.DnsName)
			{
				string dnsName = Encoding.ASCII.GetString(name.Value.Span);
				dnsNames.Add(dnsName);

				if (HostName.GetPattern(dnsName, out bool wildcard) is { } pattern)
				{
					(wildcard ? wildcardPatterns : dnsNamePatterns).Add(pattern);
				}
			}
		}

		DnsNames = dnsNames.AsReadOnly();
		_addresses = addresses;
		IPAddresses = addresses.AsReadOnly();
		_dnsNamePatterns = [.. dnsNamePatterns];
		_wildcardPatterns = [.. wildcardPatterns];
	}

	/// <summary>
	/// Gets the dNSName entries, in the order of the encoding, as they are encoded; empty if there are none.
	/// </summary>
	/// <remarks>The entries include those that <see cref="MatchesHostName" /> ignores, such as one that is empty or has a trailing dot.</remarks>
	public IReadOnlyList<string> DnsNames { get; }

	/// <summary>
	/// Gets the iPAddress entries, in the order of the encoding, each the 4 octets of an IPv4 address or the 16 octets of an IPv6 address in network byte order; empty if there are none.
	/// </summary>
	public IReadOnlyList<ReadOnlyMemory<byte>> IPAddresses { get; }

	// Every entry, in the order of the encoding.
	internal IReadOnlyList<GeneralName> Names { get; }

	/// <summary>
	/// Decodes the DER-encoded value of a subject alternative name extension.
	/// </summary>
	/// <param name="source">The contents of extnValue, a GeneralNames, with nothing after it.</param>
	/// <returns>The decoded value, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded GeneralNames.</exception>
	public static SubjectAlternativeName Decode(ReadOnlySpan<byte> source)
	{
		try
		{
			return Read(source.ToArray());
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The subject alternative name is invalid.", nameof(source), e);
		}
	}

	/// <summary>
	/// Determines whether an entry identifies a host name, as RFC 9525 specifies for TLS and DTLS.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The host name is an IP address if it is one in dotted-decimal IPv4 notation, as in RFC 3986, Sec. 3.2.2, or in IPv6 text notation (RFC 4291, Sec. 2.2), optionally in brackets as in a URI; its octets must equal those of an iPAddress entry (RFC 9525, Sec. 6.4).
	/// Otherwise it is a DNS name, without the one trailing dot that it may have: labels of 1 to 63 letters, digits and hyphens that neither start nor end with a hyphen, 253 characters at most, whose last label is not numeric, so that no notation of an IP address, such as 127.1, 0x7f.1 or 0177.0.0.1, counts as one (RFC 9525, Sec. 7.4).
	/// Labels may also hold underscores, in host names and dNSName entries alike, unless the name has labels that are not ASCII.
	/// </para>
	/// <para>
	/// A DNS name may also have labels that are not ASCII, each converted to an A-label with <see cref="System.Globalization.IdnMapping" />, among labels in ASCII, such as A-labels, which stay as they are. Such a label must be one that the platform's IDNA conversion accepts and leaves as it is, apart from the case of ASCII letters: other than letters, digits and hyphens, it may hold only letters that are not upper or title case, marks that do not start it and decimal digits, so that the result is the same on every platform that accepts the name.
	/// Names that the conversion would change, such as those with upper-case non-ASCII letters, compatibility characters or full-width dots, are rejected, as are characters that the platform's Unicode version does not know.
	/// The labels are not otherwise checked against the rules of IDNA2008 for U-labels: one that breaks its Bidi rule or a contextual rule, or that holds a code point that it disallows, may be accepted.
	/// Where the conversion neither maps nor normalizes names as IDNA requires, as in invariant globalization mode, every name with a character that is not ASCII is rejected. A-labels avoid all of these.
	/// </para>
	/// <para>
	/// A DNS name matches a dNSName entry that equals it in ASCII letters of either case (RFC 9525, Sec. 6.3), and a wildcard entry whose first label is "*" alone, which stands for exactly one label, if the rest of the host name equals the rest of the entry.
	/// Entries that do not follow the syntax above match nothing: one with a trailing dot, an empty label, a character other than a letter, digit, hyphen or underscore, "*" in another place or "*" alone, for example.
	/// DNS names never match iPAddress entries, IP addresses never match dNSName entries, and the subject's common name is not used (RFC 9525, Sec. 2).
	/// </para>
	/// </remarks>
	/// <param name="hostName">The host name: a DNS name or an IP address.</param>
	/// <returns><see langword="true" /> if an entry identifies <paramref name="hostName" />; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="hostName" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="hostName" /> is neither a DNS name nor an IP address.</exception>
	public bool MatchesHostName(string hostName)
	{
		ArgumentNullException.ThrowIfNull(hostName);

		return Matches(HostName.Parse(hostName, nameof(hostName)));
	}

	internal bool Matches(HostName hostName)
	{
		if (hostName.Address is { } address)
		{
			foreach (ReadOnlyMemory<byte> entry in _addresses)
			{
				if (entry.Span.SequenceEqual(address))
				{
					return true;
				}
			}

			return false;
		}

		string? dnsName = hostName.DnsName;
		Debug.Assert(dnsName is not null);

		foreach (string pattern in _dnsNamePatterns)
		{
			if (Ascii.EqualsIgnoreCase(dnsName, pattern))
			{
				return true;
			}
		}

		// A wildcard stands for the first label, which must not be all of the host name.
		int dot = dnsName.IndexOf('.');

		if (dot > 0)
		{
			ReadOnlySpan<char> parent = dnsName.AsSpan(dot + 1);

			foreach (string pattern in _wildcardPatterns)
			{
				if (Ascii.EqualsIgnoreCase(parent, pattern))
				{
					return true;
				}
			}
		}

		return false;
	}

	// GeneralNames, the results slices of value.
	internal static SubjectAlternativeName Read(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		GeneralName[] names = GeneralName.ReadGeneralNames(ref reader);
		reader.ThrowIfNotEmpty();
		return new SubjectAlternativeName(names);
	}
}
