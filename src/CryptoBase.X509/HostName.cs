using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace CryptoBase.X509;

// A host name to match against a certificate, the reference identifier of RFC 9525, Sec. 6.1: a DNS name in A-labels without the dot of the root, or the octets of an IPv4 or IPv6 address. The static members give the syntax of host names, for reference identifiers and for the dNSName entries that certificates present.
internal readonly struct HostName
{
	private const int MaxNameLength = 253;
	private const int MaxLabelLength = 63;
	private const int IPv4Length = 4;
	private const int IPv6Length = 16;

	private static readonly SearchValues<char> LdhCharacters = SearchValues.Create("-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
	private static readonly SearchValues<char> LabelCharacters = SearchValues.Create("-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz");
	private static readonly SearchValues<char> HexDigits = SearchValues.Create("0123456789ABCDEFabcdef");

	// Whether the platform's IDNA conversion maps and normalizes names, as ProbeIdnaMapping finds.
	private static readonly bool MapsIdna = ProbeIdnaMapping();

	private HostName(string? dnsName, byte[]? address)
	{
		DnsName = dnsName;
		Address = address;
	}

	// The DNS name, or null for an IP address.
	public string? DnsName { get; }

	// The 4 or 16 octets of the IP address, or null for a DNS name.
	public byte[]? Address { get; }

	// A host name is an IP address if it is one in a notation that RFC 9525 recognizes: dotted decimal for IPv4, as in RFC 3986, Sec. 3.2.2, and the text of RFC 4291, Sec. 2.2, for IPv6, optionally in the brackets of a URI. Otherwise it must be a DNS name: one trailing dot is removed, and labels that are not ASCII are converted to A-labels.
	public static HostName Parse(string hostName, string parameterName)
	{
		if (ParseIPAddress(hostName) is { } address)
		{
			return new HostName(null, address);
		}

		string? ascii = Ascii.IsValid(hostName) ? hostName : ToAscii(hostName);
		ReadOnlySpan<char> name = ascii;

		if (name is [.., '.'])
		{
			name = name.Slice(0, name.Length - 1);
		}

		if (ascii is null || !IsDnsName(name))
		{
			throw new ArgumentException("The host name is neither a DNS name nor an IP address.", parameterName);
		}

		return new HostName(name.Length == ascii.Length ? ascii : name.ToString(), null);
	}

	// The preferred name syntax of RFC 1034, Sec. 3.5, with a digit allowed first as in RFC 1123, Sec. 2.1, which RFC 5280, Sec. 4.2.1.6, requires of a dNSName: labels of 1 to 63 letters, digits and hyphens that neither start nor end with a hyphen, 253 characters at most, without the dot of the root.
	// Labels may also hold underscores, unless the name has U-labels.
	// The last label must not be numeric, as no top-level domain is (RFC 3696, Sec. 2), so that an IPv4 address in a shorthand notation, such as 127.1, 0x7f.1 or 0177.0.0.1, is not a DNS name either (RFC 9525, Sec. 7.4).
	public static bool IsDnsName(ReadOnlySpan<char> name)
	{
		if (name.IsEmpty || name.Length > MaxNameLength)
		{
			return false;
		}

		while (true)
		{
			int dot = name.IndexOf('.');
			ReadOnlySpan<char> label = dot < 0 ? name : name.Slice(0, dot);

			if (label.Length is 0 or > MaxLabelLength || label[0] is '-' || label[^1] is '-' || label.ContainsAnyExcept(LabelCharacters))
			{
				return false;
			}

			if (dot < 0)
			{
				return !IsNumeric(label);
			}

			name = name.Slice(dot + 1);
		}
	}

	// Labels that are not ASCII to A-labels, with the platform's IDNA conversion, or null if one is not a label that the conversion accepts and leaves as it is. The other rules of IDNA2008 for U-labels (RFC 5890, Sec. 2.3.2.1), such as its Bidi rule, its contextual rules and the code points that it disallows, are not checked.
	// The conversion maps characters, such as upper-case letters, before it encodes them, and the mapping depends on the platform's Unicode version and its globalization mode. So the name must be what the conversion leaves as it is, apart from the case of ASCII letters: besides letters, digits, hyphens and dots, only letters that are not upper or title case, marks that do not start a label (RFC 5891, Sec. 5.4) and decimal digits, the LetterDigits of RFC 5892, Sec. 2.1, that the conversion accepts and keeps. Every platform that accepts a name then gives the same A-labels, the Punycode of its labels.
	public static string? ToAscii(string hostName)
	{
		return ToAscii(hostName, MapsIdna);
	}

	// As ToAscii, with mapsIdna telling whether the conversion maps and normalizes the name as IDNA requires (RFC 5895; UTS #46), which it does not in invariant globalization mode, where it only encodes Punycode; without the mapping, a name with a character that is not ASCII is not in U-labels.
	// Each label converts on its own, so that an ASCII label, such as an A-label, stays as it is, and a U-label must convert back to itself.
	internal static string? ToAscii(string hostName, bool mapsIdna)
	{
		bool labelStart = true;
		bool ascii = true;

		foreach (Rune rune in hostName.EnumerateRunes())
		{
			UnicodeCategory category = Rune.GetUnicodeCategory(rune);
			bool letterOrDigit = category is UnicodeCategory.LowercaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.DecimalDigitNumber;
			bool mark = category is UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark;
			bool allowed = rune.IsAscii ? (char)rune.Value is '.' || LdhCharacters.Contains((char)rune.Value) : mapsIdna && (letterOrDigit || mark && !labelStart);

			if (!allowed)
			{
				return null;
			}

			ascii &= rune.IsAscii;
			labelStart = rune.Value is '.';
		}

		if (ascii)
		{
			return hostName;
		}

		IdnMapping mapping = new() { UseStd3AsciiRules = true };
		string[] labels = hostName.Split('.');

		try
		{
			for (int i = 0; i < labels.Length; ++i)
			{
				string label = labels[i];

				if (Ascii.IsValid(label))
				{
					continue;
				}

				string aLabel = mapping.GetAscii(label);
				if (mapping.GetUnicode(aLabel) != DistinguishedName.FoldAsciiCase(label))
				{
					return null;
				}

				labels[i] = aLabel;
			}
		}
		catch (ArgumentException)
		{
			return null;
		}

		return string.Join('.', labels);
	}

	// Whether the conversion maps as IDNA requires: it composes u and a combining diaeresis to the ü of "bücher", which it leaves decomposed in invariant globalization mode.
	internal static bool ProbeIdnaMapping()
	{
		try
		{
			return new IdnMapping().GetAscii("bu\u0308cher") is "xn--bcher-kva";
		}
		catch (ArgumentException)
		{
			return false;
		}
	}

	// The octets of an IP address in the notations of ReferenceIdentifier.Parse, or null. Zones, ports and shorthand notations, such as 127.1, are not IP addresses.
	public static byte[]? ParseIPAddress(ReadOnlySpan<char> source)
	{
		Span<byte> address = stackalloc byte[IPv6Length];

		if (source is ['[', .. var bracketed, ']'])
		{
			return TryParseIPv6(bracketed, address) ? address.ToArray() : null;
		}

		if (source.Contains(':'))
		{
			return TryParseIPv6(source, address) ? address.ToArray() : null;
		}

		return TryParseIPv4(source, address) ? address.Slice(0, IPv4Length).ToArray() : null;
	}

	// A label that an IPv4 parser may read as a number: decimal digits, or 0x and hexadecimal digits, as in the "ends in a number" check of the WHATWG URL Standard.
	private static bool IsNumeric(ReadOnlySpan<char> label)
	{
		return !label.ContainsAnyExceptInRange('0', '9') || label is ['0', 'x' or 'X', .. var digits] && !digits.ContainsAnyExcept(HexDigits);
	}

	// dec-octet "." dec-octet "." dec-octet "." dec-octet, each 0 to 255 without a leading zero (RFC 3986, Sec. 3.2.2).
	private static bool TryParseIPv4(ReadOnlySpan<char> source, Span<byte> destination)
	{
		for (int i = 0; i < IPv4Length; ++i)
		{
			int end = i < IPv4Length - 1 ? source.IndexOf('.') : source.Length;

			if (end is < 1 or > 3 || source.Slice(0, end).ContainsAnyExceptInRange('0', '9') || source[0] is '0' && end > 1)
			{
				return false;
			}

			int value = 0;

			foreach (char digit in source.Slice(0, end))
			{
				value = value * 10 + digit - '0';
			}

			if (value > byte.MaxValue)
			{
				return false;
			}

			destination[i] = (byte)value;
			source = source.Slice(Math.Min(end + 1, source.Length));
		}

		return true;
	}

	// Eight groups of one to four hexadecimal digits, with "::" for one or more groups of zeros, and the last two groups optionally an IPv4 address (RFC 4291, Sec. 2.2; RFC 3986, Sec. 3.2.2).
	private static bool TryParseIPv6(ReadOnlySpan<char> source, Span<byte> destination)
	{
		Span<ushort> head = stackalloc ushort[IPv6Length / 2];
		Span<ushort> tail = stackalloc ushort[IPv6Length / 2];
		int gap = source.IndexOf("::");
		int headCount;
		int tailCount = 0;

		if (gap < 0)
		{
			if (!TryParseGroups(source, head, true, out headCount) || headCount != head.Length)
			{
				return false;
			}
		}
		else if (!TryParseGroups(source.Slice(0, gap), head, false, out headCount) || !TryParseGroups(source.Slice(gap + 2), tail, true, out tailCount) || headCount + tailCount >= head.Length)
		{
			return false;
		}

		destination.Clear();

		for (int i = 0; i < headCount; ++i)
		{
			BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2 * i), head[i]);
		}

		for (int i = 0; i < tailCount; ++i)
		{
			BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(destination.Length - 2 * (tailCount - i)), tail[i]);
		}

		return true;
	}

	// Groups separated by single colons, none if source is empty; with allowIPv4, the last may be an IPv4 address, which fills two groups.
	private static bool TryParseGroups(ReadOnlySpan<char> source, Span<ushort> groups, bool allowIPv4, out int count)
	{
		count = 0;

		while (!source.IsEmpty)
		{
			int colon = source.IndexOf(':');
			ReadOnlySpan<char> group = colon < 0 ? source : source.Slice(0, colon);

			if (allowIPv4 && colon < 0 && group.Contains('.'))
			{
				Span<byte> address = stackalloc byte[IPv4Length];

				if (count > groups.Length - 2 || !TryParseIPv4(group, address))
				{
					return false;
				}

				groups[count++] = BinaryPrimitives.ReadUInt16BigEndian(address);
				groups[count++] = BinaryPrimitives.ReadUInt16BigEndian(address.Slice(2));
				return true;
			}

			if (group.Length is 0 or > 4 || group.ContainsAnyExcept(HexDigits) || count == groups.Length)
			{
				return false;
			}

			groups[count++] = ushort.Parse(group, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);

			if (colon < 0)
			{
				return true;
			}

			// A colon must be followed by a group.
			source = source.Slice(colon + 1);

			if (source.IsEmpty)
			{
				return false;
			}
		}

		return true;
	}
}
