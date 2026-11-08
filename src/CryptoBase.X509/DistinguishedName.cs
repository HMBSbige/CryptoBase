using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Unicode;

namespace CryptoBase.X509;

// A Name in the form in which RFC 5280, Sec. 7.1, compares names, with each attribute value of a string type prepared once, so that comparing many names and subtrees decodes each value only once.
// The instance is immutable, and its members are slices of the memory of the Name, which X509Name.Read has checked.
internal sealed class DistinguishedName
{
	private static readonly UTF32Encoding StrictUtf32BigEndian = new(bigEndian: true, byteOrderMark: false, throwOnInvalidCharacters: true);

	private readonly NameAttribute[][] _relativeNames;
	private readonly ReadOnlyMemory<byte> _encoded;

	private DistinguishedName(NameAttribute[][] relativeNames, ReadOnlyMemory<byte> encoded, long work)
	{
		_relativeNames = relativeNames;
		_encoded = encoded;
		Work = work;
	}

	// The cost of the Name in comparisons: one, and one for each attribute and for every 64 bytes of it, as a comparison takes time in the length of the value. The product of the costs of two Names bounds the work of comparing them.
	public long Work { get; }

	public static DistinguishedName Read(ReadOnlyMemory<byte> name)
	{
		DerReader reader = new(name);
		DerReader relativeNames = reader.ReadSequence();
		List<NameAttribute[]> parsed = [];
		List<NameAttribute> attributes = [];
		long work = 1;

		while (relativeNames.HasData)
		{
			DerReader relativeName = relativeNames.ReadSetOf();

			while (relativeName.HasData)
			{
				DerReader attribute = relativeName.ReadSequence(out ReadOnlyMemory<byte> element);
				ReadOnlyMemory<byte> type = attribute.ReadObjectIdentifierContents();
				ReadOnlyMemory<byte> value = attribute.ReadEncodedValue();
				attributes.Add(new NameAttribute(type, value, Prepare(value.Span)));
				work += 1 + (element.Length >> 6);
			}

			parsed.Add([.. attributes]);
			attributes.Clear();
		}

		return new DistinguishedName([.. parsed], name, work);
	}

	// RFC 5280, Sec. 7.1: a Name is within a subtree if it has at least as many relative names, and those of the subtree match its first ones in order; the empty Name is the subtree of every Name.
	public bool IsWithin(DistinguishedName subtree)
	{
		return IsWithin(subtree, exact: true);
	}

	// Whether the Name could be within the subtree if the comparison applied the case folding and the normalization of RFC 4518 that it leaves out: as IsWithin, with an attribute that holds a character that they could change compared only as far as MightMatch can.
	public bool MightBeWithin(DistinguishedName subtree)
	{
		return IsWithin(subtree, exact: false);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool IsWithin(DistinguishedName subtree, bool exact)
	{
		NameAttribute[][] names = _relativeNames;
		NameAttribute[][] bases = subtree._relativeNames;

		if (names.Length < bases.Length)
		{
			return false;
		}

		for (int i = 0; i < bases.Length; ++i)
		{
			if (!(exact ? Match(names[i], bases[i]) : MightMatch(names[i], bases[i])))
			{
				return false;
			}
		}

		return true;
	}

	public string Describe()
	{
		try
		{
			return PathProblem.Escape(new X500DistinguishedName(_encoded.Span).Name);
		}
		catch (CryptographicException)
		{
			return "";
		}
	}

	// RFC 5280, Sec. 7.1: two relative names match if they have the same number of attributes, each with a match in the other. Matching is an equivalence, so pairing each attribute with a distinct one compares the two as sets with their multiplicities.
	private static bool Match(NameAttribute[] left, NameAttribute[] right)
	{
		if (left.Length != right.Length)
		{
			return false;
		}

		if (left.Length is 1)
		{
			return left[0].Matches(right[0]);
		}

		Span<bool> used = left.Length <= 64 ? stackalloc bool[64] : new bool[left.Length];

		foreach (NameAttribute attribute in left)
		{
			int match = 0;

			while (match < right.Length && (used[match] || !attribute.Matches(right[match])))
			{
				++match;
			}

			if (match == right.Length)
			{
				return false;
			}

			used[match] = true;
		}

		return true;
	}

	// Whether two relative names could match if the comparison were complete. A lone attribute compares by the characters that an unstable one cannot change. Among several, an attribute with an unstable character may stand for any of its type, and one without only for its equal or such an attribute: pairing those without with their equals first, then with those with one, leaves the attributes with one to pair with what remains, so that a match is found if there is one.
	private static bool MightMatch(NameAttribute[] left, NameAttribute[] right)
	{
		if (left.Length != right.Length)
		{
			return false;
		}

		if (left.Length is 1)
		{
			return left[0].MightMatchAlone(right[0]);
		}

		Span<bool> leftUsed = left.Length <= 64 ? stackalloc bool[64] : new bool[left.Length];
		Span<bool> rightUsed = left.Length <= 64 ? stackalloc bool[64] : new bool[left.Length];

		for (int pass = 0; pass < 3; ++pass)
		{
			bool unstable = pass is 2;

			for (int i = 0; i < left.Length; ++i)
			{
				if (leftUsed[i] || left[i].IsUnstable != unstable)
				{
					continue;
				}

				int match = 0;

				while (match < right.Length && (rightUsed[match] || !(pass is 0 ? !right[match].IsUnstable && left[i].Matches(right[match]) : left[i].MightMatch(right[match]))))
				{
					++match;
				}

				if (match < right.Length)
				{
					leftUsed[i] = true;
					rightUsed[match] = true;
				}
				else if (pass > 0)
				{
					return false;
				}
			}
		}

		return true;
	}

	// The prepared form of an attribute value of a string type, or null for a value of another type or one that does not decode, which only compares byte for byte.
	private static string? Prepare(ReadOnlySpan<byte> element)
	{
		return Decode(element) is { } text ? Normalize(text) : null;
	}

	// The text of a value of a string type that RFC 5280 uses in a Name, without checks beyond its encoding: the characters of the ASCII types may be outside their alphabets, as CAs put in them. TeletexString is read as UTF-8 if valid and otherwise as ISO 8859-1.
	private static string? Decode(ReadOnlySpan<byte> element)
	{
		Asn1Tag tag = Asn1Tag.Decode(element, out _);

		if (tag.TagClass is not TagClass.Universal || tag.IsConstructed)
		{
			return null;
		}

		UniversalTagNumber number = (UniversalTagNumber)tag.TagValue;

		if (number is not (UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString or UniversalTagNumber.IA5String or UniversalTagNumber.VisibleString or UniversalTagNumber.T61String or UniversalTagNumber.BMPString or UniversalTagNumber.UniversalString))
		{
			return null;
		}

		AsnDecoder.ReadEncodedValue(element, AsnEncodingRules.DER, out int offset, out int length, out _);
		ReadOnlySpan<byte> contents = element.Slice(offset, length);

		try
		{
			return number switch
			{
				UniversalTagNumber.UTF8String => Utf8.IsValid(contents) ? Encoding.UTF8.GetString(contents) : null,
				UniversalTagNumber.PrintableString or UniversalTagNumber.IA5String or UniversalTagNumber.VisibleString => Ascii.IsValid(contents) ? Encoding.ASCII.GetString(contents) : null,
				UniversalTagNumber.UniversalString => StrictUtf32BigEndian.GetString(contents),
				_ => AsnDecoder.ReadCharacterString(element, AsnEncodingRules.DER, number, out _)
			};
		}
		catch (Exception e) when (e is AsnContentException or DecoderFallbackException)
		{
			return null;
		}
	}

	// The mapping of RFC 4518, Sec. 2.2, without the case folding of other than ASCII letters, and the insignificant space handling of Sec. 2.6.1: ASCII letters to lower case, the characters that Sec. 2.2 maps to nothing removed and those that it maps to a space taken as one, and spaces removed at both ends and reduced to one elsewhere.
	// Other characters stay as they are, compared by code point; case folding of the others and normalization are not applied, so that the result does not depend on the globalization mode. MightBeWithin tells when applying them could change it.
	private static string Normalize(string text)
	{
		Span<char> buffer = text.Length <= 256 ? stackalloc char[256] : new char[text.Length];
		int length = 0;
		bool space = false;

		for (int i = 0; i < text.Length; ++i)
		{
			char c = text[i];

			// The only code points of Sec. 2.2 outside the Basic Multilingual Plane, all mapped to nothing: U+1D173 to U+1D17A, U+E0001 and U+E0020 to U+E007F.
			if (char.IsHighSurrogate(c) && i + 1 < text.Length && (c is '\uD834' && text[i + 1] is >= '\uDD73' and <= '\uDD7A' || c is '\uDB40' && text[i + 1] is '\uDC01' or (>= '\uDC20' and <= '\uDC7F')))
			{
				++i;
				continue;
			}

			if (IsMappedToNothing(c))
			{
				continue;
			}

			if (IsMappedToSpace(c))
			{
				space = length > 0;
				continue;
			}

			if (space)
			{
				buffer[length++] = ' ';
				space = false;
			}

			buffer[length++] = char.IsAsciiLetterUpper(c) ? (char)(c | 0x20) : c;
		}

		return new string(buffer.Slice(0, length));
	}

	// RFC 4518, Sec. 2.2: the control codes, the code points with a control function, and the others that the section maps to nothing.
	private static bool IsMappedToNothing(char c)
	{
		return c is <= '\u0008' or (>= '\u000E' and <= '\u001F') or (>= '\u007F' and <= '\u0084') or (>= '\u0086' and <= '\u009F')
			or '\u00AD' or '\u034F' or '\u06DD' or '\u070F' or '\u1806' or (>= '\u180B' and <= '\u180E')
			or (>= '\u200B' and <= '\u200F') or (>= '\u202A' and <= '\u202E') or (>= '\u2060' and <= '\u2063') or (>= '\u206A' and <= '\u206F')
			or (>= '\uFE00' and <= '\uFE0F') or '\uFEFF' or (>= '\uFFF9' and <= '\uFFFC');
	}

	// RFC 4518, Sec. 2.2: white space and the other separators that the section maps to a space.
	private static bool IsMappedToSpace(char c)
	{
		return c is ' ' or (>= '\t' and <= '\r') or '\u0085' or '\u00A0' or '\u1680' or (>= '\u2000' and <= '\u200A') or '\u2028' or '\u2029' or '\u202F' or '\u205F' or '\u3000';
	}

	// Whether the case folding or the normalization of RFC 4518 could change a character of a prepared text by itself: any beyond ASCII but those of the CJK Unified Ideographs and their Extension A, the Hangul Syllables, Hiragana and Katakana, which neither maps.
	private static bool IsUnstableCharacter(char c)
	{
		return c is >= '\u0080' and not (>= '\u3400' and <= '\u4DBF' or >= '\u4E00' and <= '\u9FFF' or >= '\uAC00' and <= '\uD7A3' or >= '\u3041' and <= '\u3096' or '\u309D' or '\u309E' or >= '\u30A1' and <= '\u30FE');
	}

	private static bool HasUnstableCharacter(string text)
	{
		foreach (char c in text)
		{
			if (IsUnstableCharacter(c))
			{
				return true;
			}
		}

		return false;
	}

	// Whether two prepared texts, at least one with an unstable character, could be equal if the comparison were complete. An unstable character could become any text, so only the characters out of its reach must be the same: those from each end up to the first unstable one and, from the left, up to the character before it, which could compose with it (RFC 4518, Sec. 2.3).
	private static bool MightEqual(string left, string right)
	{
		int length = Math.Min(left.Length, right.Length);

		for (int i = 0; i < length; ++i)
		{
			if (IsUnstableCharacter(left[i]) || IsUnstableCharacter(right[i]) || i + 1 < left.Length && IsUnstableCharacter(left[i + 1]) || i + 1 < right.Length && IsUnstableCharacter(right[i + 1]))
			{
				break;
			}

			if (left[i] != right[i])
			{
				return false;
			}
		}

		for (int i = 1; i <= length && !IsUnstableCharacter(left[^i]) && !IsUnstableCharacter(right[^i]); ++i)
		{
			if (left[^i] != right[^i])
			{
				return false;
			}
		}

		return true;
	}

	// Type is the contents of the OBJECT IDENTIFIER, Value the DER of the value, and Text its prepared form, or null if it has none.
	private readonly struct NameAttribute(ReadOnlyMemory<byte> type, ReadOnlyMemory<byte> value, string? text)
	{
		private readonly ReadOnlyMemory<byte> _type = type;
		private readonly ReadOnlyMemory<byte> _value = value;
		private readonly string? _text = text;

		// Whether the prepared text has a character that the comparison cannot settle.
		public bool IsUnstable { get; } = text is not null && HasUnstableCharacter(text);

		// RFC 5280, Sec. 7.1: the types are the same, and the values are identical or equal once prepared.
		public bool Matches(in NameAttribute other)
		{
			return _type.Span.SequenceEqual(other._type.Span) && (_value.Span.SequenceEqual(other._value.Span) || _text is not null && _text == other._text);
		}

		// Matches, or could if the comparison were complete, whatever the rest of the value: an attribute with an unstable character may stand for any of its type, as the pairing of several attributes needs.
		public bool MightMatch(in NameAttribute other)
		{
			return (IsUnstable || other.IsUnstable) && _type.Span.SequenceEqual(other._type.Span) || Matches(other);
		}

		// MightMatch for the only attribute of a relative name, where the prepared texts narrow it down to the values that MightEqual cannot tell apart.
		public bool MightMatchAlone(in NameAttribute other)
		{
			if (_text is null || other._text is null || !IsUnstable && !other.IsUnstable)
			{
				return MightMatch(other);
			}

			return _type.Span.SequenceEqual(other._type.Span) && MightEqual(_text, other._text);
		}
	}
}
