using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Unicode;

namespace CryptoBase.X509;

// A Name in the form in which RFC 5280, Sec. 7.1, compares names, with each attribute value of a string type prepared once, so that comparing many names and subtrees decodes each value only once.
// The instance is immutable, and its members are slices of the memory of the Name, which X509Name.Read has checked.
internal sealed class DistinguishedName
{
	// The bound on the product of the costs of two Names that AreEqual compares: the product bounds the work of comparing the attributes of a relative name with each other's.
	public const long MaxEqualityWork = 1 << 20;

	private static readonly UTF32Encoding StrictUtf32BigEndian = new(bigEndian: true, byteOrderMark: false, throwOnInvalidCharacters: true);

	// id-domainComponent, 0.9.2342.19200300.100.1.25 (RFC 5280, Appendix A.1), as the contents of the OBJECT IDENTIFIER.
	private static ReadOnlySpan<byte> DomainComponentOid => [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19];

	// emailAddress and unstructuredName, 1.2.840.113549.1.9.1 and 1.2.840.113549.1.9.2 (RFC 2985, Secs. 5.2.1 and 5.2.2), as the contents of the OBJECT IDENTIFIER.
	internal static ReadOnlySpan<byte> EmailAddressOid => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01];
	private static ReadOnlySpan<byte> UnstructuredNameOid => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02];

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
				string? text = Prepare(type.Span, value.Span, out string? prepared, out bool shortened);
				attributes.Add(new NameAttribute(type, value, text, prepared, shortened));
				work += 1 + (element.Length >> 6);
			}

			parsed.Add([.. attributes]);
			attributes.Clear();
		}

		return new DistinguishedName([.. parsed], name, work);
	}

	// RFC 5280, Sec. 7.1: two Names are the same if they have as many relative names, and each matches the other's at its place, by the exact comparison of IsWithin, so that names are never found the same that a complete comparison would tell apart.
	// Names that are not identical are first compared without allocating, as Names that differ in the letters and digits of a value of an ASCII string type differ once prepared too. A Name that does not decode, or a pair whose comparison could take more than MaxEqualityWork, counts as different.
	public static bool AreEqual(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right)
	{
		if (left.Span.SequenceEqual(right.Span))
		{
			return true;
		}

		try
		{
			if (!MightBeEqual(left, right))
			{
				return false;
			}

			DistinguishedName first = Read(left);
			DistinguishedName second = Read(right);
			return first._relativeNames.Length == second._relativeNames.Length && first.Work <= MaxEqualityWork / second.Work && first.IsWithin(second);
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// Whether two Names could be the same: as many relative names, and in each pair of relative names of one attribute, the same type and values that are identical or of which the letters and digits could be the same once prepared.
	private static bool MightBeEqual(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right)
	{
		DerReader leftNames = new DerReader(left).ReadSequence();
		DerReader rightNames = new DerReader(right).ReadSequence();

		while (leftNames.HasData && rightNames.HasData)
		{
			DerReader leftName = leftNames.ReadSetOf();
			DerReader rightName = rightNames.ReadSetOf();
			DerReader leftAttribute = leftName.ReadSequence();
			DerReader rightAttribute = rightName.ReadSequence();

			// A relative name of several attributes compares as a set, which Read is left to.
			if (leftName.HasData || rightName.HasData)
			{
				continue;
			}

			if (!leftAttribute.ReadObjectIdentifierContents().Span.SequenceEqual(rightAttribute.ReadObjectIdentifierContents().Span) || !MightBeEqualValues(leftAttribute.ReadEncodedValue().Span, rightAttribute.ReadEncodedValue().Span))
			{
				return false;
			}
		}

		return leftNames.HasData == rightNames.HasData;
	}

	// Values that are not identical, of the string types whose ASCII characters are the bytes of their contents, are equal once prepared only if their ASCII letters and digits are the same but for case: Decode keeps them, as does every form in which a value compares, and a value that does not decode compares byte for byte. Values of the other types could be equal.
	private static bool MightBeEqualValues(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
	{
		if (left.SequenceEqual(right) || !IsAsciiBytesString(left) || !IsAsciiBytesString(right))
		{
			return true;
		}

		ReadOnlySpan<byte> leftContents = GetContents(left);
		ReadOnlySpan<byte> rightContents = GetContents(right);
		int i = 0;
		int j = 0;

		while (true)
		{
			while (i < leftContents.Length && !char.IsAsciiLetterOrDigit((char)leftContents[i]))
			{
				++i;
			}

			while (j < rightContents.Length && !char.IsAsciiLetterOrDigit((char)rightContents[j]))
			{
				++j;
			}

			if (i == leftContents.Length || j == rightContents.Length)
			{
				return i == leftContents.Length && j == rightContents.Length;
			}

			if ((leftContents[i] | 0x20) != (rightContents[j] | 0x20))
			{
				return false;
			}

			++i;
			++j;
		}

		static bool IsAsciiBytesString(ReadOnlySpan<byte> element)
		{
			return element.Length > 0 && (UniversalTagNumber)element[0] is UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString or UniversalTagNumber.IA5String or UniversalTagNumber.VisibleString;
		}
	}

	// RFC 5280, Sec. 7.1: a Name is within a subtree if it has at least as many relative names, and those of the subtree match its first ones in order; the empty Name is the subtree of every Name.
	public bool IsWithin(DistinguishedName subtree)
	{
		return IsWithin(subtree, exact: true);
	}

	// Whether the Name could be within the subtree if the comparison applied the case folding and the normalization of RFC 4518 that it leaves out, or for a type compared by a case-insensitive exact match the case folding beyond ASCII or the preparation of RFC 4518 that a relying party could apply instead: as IsWithin, with an attribute that holds a character that they could change compared only as far as MightMatch can.
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
	// Equal here means equal once prepared by RFC 4518 (MatchesPrepared), which is an equivalence, as the pairing needs, and holds for every pair of stable attributes that Matches does.
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

				while (match < right.Length && (rightUsed[match] || !(pass is 0 ? !right[match].IsUnstable && left[i].MatchesPrepared(right[match]) : left[i].MightMatch(right[match]))))
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

	// The form in which an attribute value of a string type compares, or null for a value of another type or one that does not decode, which only compares byte for byte; shortened as Normalize gives it. prepared is the form that RFC 4518 gives the value where it differs, and null otherwise.
	// RFC 5280, Sec. 7.1, leaves domainComponent to Sec. 7.3, which asks for a case-insensitive exact match: its value keeps every character, with only ASCII letters folded. The rule follows the type of the attribute, so a value in another string type than the IA5String that Appendix A.1 gives it, as some CAs encode it, compares by the same rule; a character beyond ASCII stays unstable, as case folding could reach it.
	// LDAP compares the type by caseIgnoreIA5Match instead (RFC 4519), which ignores insignificant spaces (RFC 4517, Sec. 4.2.7), so that a relying party could take values equal once prepared by RFC 4518 for the same name: MightBeWithin compares those too, so that such a value cannot escape an excluded subtree. Its shortened is left out, as MightBeWithin only widens without it.
	// emailAddress and unstructuredName compare the same way. RFC 2985, Secs. 5.2.1 and 5.2.2, gives them pkcs9CaseIgnoreMatch, which Sec. 6.1 defines as strings of the same length with the same characters but for case, so that white space is significant; RFC 5280, Sec. 4.1.2.6, also takes emailAddress values as not case-sensitive. RFC 5280, Sec. 7.1, only requires caseIgnoreMatch and makes other matching rules optional, so the exact match narrows permitted subtrees beyond what it asks, and a relying party with caseIgnoreMatch alone prepares these values by RFC 4518, which MightBeWithin compares too.
	private static string? Prepare(ReadOnlySpan<byte> type, ReadOnlySpan<byte> element, out string? prepared, out bool shortened)
	{
		prepared = null;
		shortened = false;

		if (Decode(element) is not { } text)
		{
			return null;
		}

		if (!(type.SequenceEqual(DomainComponentOid) || type.SequenceEqual(EmailAddressOid) || type.SequenceEqual(UnstructuredNameOid)))
		{
			return Normalize(text, out shortened);
		}

		string folded = FoldAsciiCase(text);
		string normalized = Normalize(text, out _);
		prepared = normalized == folded ? null : normalized;
		return folded;
	}

	internal static string FoldAsciiCase(string text)
	{
		return string.Create(text.Length, text, static (buffer, source) =>
		{
			for (int i = 0; i < source.Length; ++i)
			{
				buffer[i] = FoldAsciiCase(source[i]);
			}
		});
	}

	private static char FoldAsciiCase(char c)
	{
		return char.IsAsciiLetterUpper(c) ? (char)(c | 0x20) : c;
	}

	private static ReadOnlySpan<byte> GetContents(ReadOnlySpan<byte> element)
	{
		return new ValueAsnReader(element, AsnEncodingRules.DER).PeekContentBytes();
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

		ReadOnlySpan<byte> contents = GetContents(element);

		try
		{
			return number switch
			{
				UniversalTagNumber.UTF8String => Utf8.IsValid(contents) ? Encoding.UTF8.GetString(contents) : null,
				UniversalTagNumber.PrintableString or UniversalTagNumber.IA5String or UniversalTagNumber.VisibleString => Ascii.IsValid(contents) ? Encoding.ASCII.GetString(contents) : null,
				UniversalTagNumber.UniversalString => StrictUtf32BigEndian.GetString(contents),
				_ => new ValueAsnReader(element, AsnEncodingRules.DER).ReadCharacterString(number)
			};
		}
		catch (Exception e) when (e is AsnContentException or DecoderFallbackException)
		{
			return null;
		}
	}

	// The mapping of RFC 4518, Sec. 2.2, without the case folding of other than ASCII letters, and the insignificant space handling of Sec. 2.6.1: ASCII letters to lower case, the characters that Sec. 2.2 maps to nothing removed and those that it maps to a space taken as one, and spaces removed at both ends and reduced to one elsewhere.
	// Other characters stay as they are, compared by code point; case folding of the others and normalization are not applied, so that the result does not depend on the globalization mode. MightBeWithin tells when applying them could change it.
	// Sec. 2.6.1 keeps a space that a combining mark follows, and an unstable character could be one or begin with one once folded and normalized (U+FF9E becomes U+3099): before such a character, the spaces at the start and those after the first elsewhere could count. shortened tells whether any of those was removed, so that equal texts do not show the values equal.
	private static string Normalize(string text, out bool shortened)
	{
		Span<char> buffer = text.Length <= 256 ? stackalloc char[256] : new char[text.Length];
		int length = 0;
		int spaces = 0;
		shortened = false;

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
				++spaces;
				continue;
			}

			if (spaces > 0)
			{
				// None of the spaces at the start is kept, and one of those elsewhere.
				bool start = length is 0;
				shortened |= (start || spaces > 1) && IsUnstableCharacter(c);

				if (!start)
				{
					buffer[length++] = ' ';
				}

				spaces = 0;
			}

			buffer[length++] = FoldAsciiCase(c);
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

	// Type is the contents of the OBJECT IDENTIFIER, Value the DER of the value, and Text the form in which it compares, or null if it has none; Prepared is the form that RFC 4518 gives it where that differs, as for a type compared by a case-insensitive exact match, and null otherwise; Shortened tells whether preparing Text removed spaces that a complete comparison could keep, which Normalize gives.
	private readonly struct NameAttribute(ReadOnlyMemory<byte> type, ReadOnlyMemory<byte> value, string? text, string? prepared, bool shortened)
	{
		private readonly ReadOnlyMemory<byte> _type = type;
		private readonly ReadOnlyMemory<byte> _value = value;
		private readonly string? _text = text;
		private readonly string? _prepared = prepared;
		private readonly bool _shortened = shortened;
		private readonly bool _preparedUnstable = prepared is not null && HasUnstableCharacter(prepared);

		// Whether Text has a character that the comparison cannot settle. The form of RFC 4518 only removes characters of Text and turns some into spaces, so that it has such a character only if Text does.
		public bool IsUnstable { get; } = text is not null && HasUnstableCharacter(text);

		// RFC 5280, Sec. 7.1: the types are the same, and the values are identical or equal once prepared. Prepared texts of which either lost spaces before an unstable character do not show the values equal, as those spaces could make them differ.
		public bool Matches(in NameAttribute other)
		{
			return HasTypeOf(other) && (_value.Span.SequenceEqual(other._value.Span) || _text is not null && _text == other._text && !_shortened && !other._shortened);
		}

		// Matches, or the values are equal in the form of RFC 4518, by which LDAP compares a domainComponent and a relying party with caseIgnoreMatch alone an emailAddress or unstructuredName. Between stable attributes, this is an equivalence that holds wherever Matches does: values identical or equal as Text are equal in that form, and a stable one shortens nothing.
		public bool MatchesPrepared(in NameAttribute other)
		{
			return Matches(other) || (_prepared is not null || other._prepared is not null) && HasTypeOf(other) && (_prepared ?? _text) is { } prepared && prepared == (other._prepared ?? other._text);
		}

		// MatchesPrepared, or could match if the comparison were complete, whatever the rest of the value: an attribute with an unstable character may stand for any of its type, as the pairing of several attributes needs.
		public bool MightMatch(in NameAttribute other)
		{
			return (IsUnstable || other.IsUnstable) && HasTypeOf(other) || MatchesPrepared(other);
		}

		// MightMatch for the only attribute of a relative name, where the texts narrow it down to the values that MightEqual cannot tell apart, in Text or in the form of RFC 4518.
		public bool MightMatchAlone(in NameAttribute other)
		{
			if (_text is null || other._text is null || !IsUnstable && !other.IsUnstable)
			{
				return MightMatch(other);
			}

			if (!HasTypeOf(other))
			{
				return false;
			}

			if (MightEqual(_text, other._text))
			{
				return true;
			}

			if (_prepared is null && other._prepared is null)
			{
				return false;
			}

			// The form of RFC 4518, as for a type compared by a case-insensitive exact match: equal, or not told apart by MightEqual if either has an unstable character.
			string left = _prepared ?? _text;
			string right = other._prepared ?? other._text;
			bool unstable = (_prepared is null ? IsUnstable : _preparedUnstable) || (other._prepared is null ? other.IsUnstable : other._preparedUnstable);
			return unstable ? MightEqual(left, right) : left == right;
		}

		private bool HasTypeOf(in NameAttribute other)
		{
			return _type.Span.SequenceEqual(other._type.Span);
		}
	}
}
