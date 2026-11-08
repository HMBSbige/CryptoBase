using System.Runtime.CompilerServices;

namespace CryptoBase.X509;

// Reads DER values in order from memory that the caller owns, and returns slices of it rather than copies. Unlike AsnReader, a class, it allocates nothing for the structures that it enters. Malformed input throws AsnContentException.
// The common forms are read here and everything else, valid or not, is left to AsnDecoder, which gives the same result and the error; a form that is read here is one that AsnDecoder accepts.
internal struct DerReader(ReadOnlyMemory<byte> source)
{
	private const byte IntegerTag = 0x02;
	private const byte BitStringTag = 0x03;
	private const byte OctetStringTag = 0x04;
	private const byte ObjectIdentifierTag = 0x06;
	private const byte SequenceTag = 0x30;
	private const byte SetTag = 0x31;

	// The longest contents of an OBJECT IDENTIFIER read here. They hold at most 19 arcs and 126 bits in a subidentifier, within the limits of AsnDecoder, which reads the longer ones.
	private const int MaxObjectIdentifierLength = 18;

	private ReadOnlyMemory<byte> _remaining = source;

	public readonly bool HasData => !_remaining.IsEmpty;

	public readonly ReadOnlyMemory<byte> GetRemaining()
	{
		return _remaining;
	}

	public readonly bool PeekTagIs(Asn1Tag tag)
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (source.IsEmpty)
		{
			return false;
		}

		// A tag number below 31 is all in the first octet; AsnDecoder reads the longer forms.
		if ((source[0] & 0x1F) is 0x1F || tag.TagValue >= 31)
		{
			return Asn1Tag.Decode(source, out _) == tag;
		}

		return source[0] == ((int)tag.TagClass | (tag.IsConstructed ? 0x20 : 0) | tag.TagValue);
	}

	public readonly void ThrowIfNotEmpty()
	{
		if (HasData)
		{
			throw new AsnContentException();
		}
	}

	public readonly void ThrowIfEmpty()
	{
		if (!HasData)
		{
			throw new AsnContentException();
		}
	}

	// A SEQUENCE, or the constructed value with tag; returns a reader of its contents and, in element, the whole value.
	public DerReader ReadSequence(out ReadOnlyMemory<byte> element, Asn1Tag? tag = null)
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (tag is not null || !TryReadHeader(source, SequenceTag, out int offset, out int length))
		{
			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out length, out _, tag);
		}

		element = Take(offset + length);
		return new DerReader(element.Slice(offset, length));
	}

	public DerReader ReadSequence(Asn1Tag? tag = null)
	{
		return ReadSequence(out _, tag);
	}

	// A SET OF, or the constructed value with tag, whose elements are in the order that DER requires.
	public DerReader ReadSetOf(Asn1Tag? tag = null)
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		// A single element is in order; AsnDecoder compares the elements of a longer SET OF.
		if (tag is not null || !TryReadHeader(source, SetTag, out int offset, out int length) || !IsSingleValue(source.Slice(offset, length)))
		{
			AsnDecoder.ReadSetOf(source, AsnEncodingRules.DER, out offset, out length, out _, expectedTag: tag);
		}

		return new DerReader(Take(offset + length).Slice(offset, length));
	}

	// One value of any type, whole.
	public ReadOnlyMemory<byte> ReadEncodedValue()
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (!TryReadHeader(source, out int offset, out int length))
		{
			AsnDecoder.ReadEncodedValue(source, AsnEncodingRules.DER, out offset, out length, out _);
		}

		return Take(offset + length);
	}

	public string ReadObjectIdentifier()
	{
		string value = AsnDecoder.ReadObjectIdentifier(_remaining.Span, AsnEncodingRules.DER, out int consumed);
		Take(consumed);
		return value;
	}

	// An OBJECT IDENTIFIER whose value the caller does not need, without the string that ReadObjectIdentifier builds for one that it does not know.
	public void SkipObjectIdentifier()
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (TryReadHeader(source, ObjectIdentifierTag, out int offset, out int length) && IsShortObjectIdentifier(source.Slice(offset, length)))
		{
			Take(offset + length);
		}
		else
		{
			ReadObjectIdentifier();
		}
	}

	// The contents of an OBJECT IDENTIFIER, without the string that ReadObjectIdentifier builds; DER has one encoding of each, so equal identifiers have equal contents.
	public ReadOnlyMemory<byte> ReadObjectIdentifierContents()
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (TryReadHeader(source, ObjectIdentifierTag, out int offset, out int length) && IsShortObjectIdentifier(source.Slice(offset, length)))
		{
			return TakeContents(offset + length, length);
		}

		AsnDecoder.ReadObjectIdentifier(source, AsnEncodingRules.DER, out int consumed);
		AsnDecoder.ReadEncodedValue(source, AsnEncodingRules.DER, out offset, out length, out _);
		return Take(consumed).Slice(offset, length);
	}

	// The contents of an INTEGER, which DER requires to be minimal, under tag if it is implicitly tagged.
	public ReadOnlyMemory<byte> ReadIntegerBytes(Asn1Tag? tag = null)
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (tag is null && TryReadHeader(source, IntegerTag, out int offset, out int length) && IsMinimalInteger(source.Slice(offset, length)))
		{
			return TakeContents(offset + length, length);
		}

		ReadOnlySpan<byte> value = AsnDecoder.ReadIntegerBytes(source, AsnEncodingRules.DER, out int consumed, tag);
		return TakeContents(consumed, value.Length);
	}

	public int ReadInt32()
	{
		if (!AsnDecoder.TryReadInt32(_remaining.Span, AsnEncodingRules.DER, out int value, out int consumed))
		{
			throw new AsnContentException();
		}

		Take(consumed);
		return value;
	}

	public bool ReadBoolean(Asn1Tag? tag = null)
	{
		bool value = AsnDecoder.ReadBoolean(_remaining.Span, AsnEncodingRules.DER, out int consumed, tag);
		Take(consumed);
		return value;
	}

	// A NULL, or the primitive value with tag.
	public void ReadNull(Asn1Tag? tag = null)
	{
		AsnDecoder.ReadNull(_remaining.Span, AsnEncodingRules.DER, out int consumed, tag);
		Take(consumed);
	}

	// The contents of an ENUMERATED, which DER requires to be minimal.
	public ReadOnlyMemory<byte> ReadEnumeratedBytes()
	{
		ReadOnlySpan<byte> value = AsnDecoder.ReadEnumeratedBytes(_remaining.Span, AsnEncodingRules.DER, out int consumed);
		return TakeContents(consumed, value.Length);
	}

	// The bits of a BIT STRING; wholeBytes rejects one with unused bits.
	public ReadOnlyMemory<byte> ReadBitString(Asn1Tag? tag = null, bool wholeBytes = true)
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		// The first octet of the contents is the number of unused bits; with none, whatever follows is valid.
		if (tag is null && TryReadHeader(source, BitStringTag, out int offset, out int length) && length > 0 && source[offset] is 0)
		{
			return TakeContents(offset + length, length - 1);
		}

		if (!AsnDecoder.TryReadPrimitiveBitString(source, AsnEncodingRules.DER, out int unusedBits, out ReadOnlySpan<byte> value, out int consumed, tag) || wholeBytes && unusedBits is not 0)
		{
			throw new AsnContentException();
		}

		return TakeContents(consumed, value.Length);
	}

	public ReadOnlyMemory<byte> ReadOctetString()
	{
		ReadOnlySpan<byte> source = _remaining.Span;

		if (TryReadHeader(source, OctetStringTag, out int offset, out int length))
		{
			return TakeContents(offset + length, length);
		}

		if (!AsnDecoder.TryReadPrimitiveOctetString(source, AsnEncodingRules.DER, out ReadOnlySpan<byte> value, out int consumed))
		{
			throw new AsnContentException();
		}

		return TakeContents(consumed, value.Length);
	}

	// A value with exactly this tag, as TryReadHeader below reads its length.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryReadHeader(ReadOnlySpan<byte> source, byte tag, out int offset, out int length)
	{
		if (source.IsEmpty || source[0] != tag)
		{
			(offset, length) = (0, 0);
			return false;
		}

		return TryReadLength(source, out offset, out length);
	}

	// A value of any type whose tag is one octet, which DER has for tag numbers up to 30. Number 0 is left to AsnDecoder, as for the universal class it marks the end of contents.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryReadHeader(ReadOnlySpan<byte> source, out int offset, out int length)
	{
		if (source.IsEmpty || (source[0] & 0x1F) is 0 or 0x1F)
		{
			(offset, length) = (0, 0);
			return false;
		}

		return TryReadLength(source, out offset, out length);
	}

	// X.690, Sec. 10.1: the long form must use the fewest octets, so these are the only forms that DER allows for that many contents. The contents are within source. Longer values, and indefinite lengths, which are invalid, are left to AsnDecoder.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryReadLength(ReadOnlySpan<byte> source, out int offset, out int length)
	{
		(offset, length) = (0, 0);

		if (source.Length < 2)
		{
			return false;
		}

		int first = source[1];

		if (first < 0x80)
		{
			(offset, length) = (2, first);
		}
		else if (first is 0x81 && source.Length >= 3 && source[2] >= 0x80)
		{
			(offset, length) = (3, source[2]);
		}
		else if (first is 0x82 && source.Length >= 4 && source[2] is not 0)
		{
			(offset, length) = (4, source[2] << 8 | source[3]);
		}
		else
		{
			return false;
		}

		return length <= source.Length - offset;
	}

	// The contents of an INTEGER are minimal if they are at least one octet and the first nine bits are not all equal (X.690, Sec. 8.3.2).
	private static bool IsMinimalInteger(ReadOnlySpan<byte> contents)
	{
		if (contents.IsEmpty)
		{
			return false;
		}

		return contents.Length is 1 || (contents[0] << 8 | contents[1] & 0x80) is not (0 or 0xFF80);
	}

	// X.690, Sec. 8.19: at least one subidentifier, each in base 128 with no leading zero, and the last one complete; and no longer than the contents read here.
	private static bool IsShortObjectIdentifier(ReadOnlySpan<byte> contents)
	{
		if (contents.IsEmpty || contents.Length > MaxObjectIdentifierLength || contents[^1] >= 0x80)
		{
			return false;
		}

		bool first = true;

		foreach (byte b in contents)
		{
			if (first && b is 0x80)
			{
				return false;
			}

			first = b < 0x80;
		}

		return true;
	}

	private static bool IsSingleValue(ReadOnlySpan<byte> contents)
	{
		return TryReadHeader(contents, out int offset, out int length) && offset + length == contents.Length;
	}

	private ReadOnlyMemory<byte> Take(int length)
	{
		ReadOnlyMemory<byte> value = _remaining.Slice(0, length);
		_remaining = _remaining.Slice(length);
		return value;
	}

	// The last contentsLength bytes of the consumed value.
	private ReadOnlyMemory<byte> TakeContents(int consumed, int contentsLength)
	{
		return Take(consumed).Slice(consumed - contentsLength);
	}
}
