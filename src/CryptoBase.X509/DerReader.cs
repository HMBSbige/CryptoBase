namespace CryptoBase.X509;

// Reads DER values in order from memory that the caller owns, and returns slices of it rather than copies. Unlike AsnReader, a class, it allocates nothing for the structures that it enters. Malformed input throws AsnContentException.
internal struct DerReader(ReadOnlyMemory<byte> source)
{
	private ReadOnlyMemory<byte> _remaining = source;

	public readonly bool HasData => !_remaining.IsEmpty;

	public readonly bool PeekTagIs(Asn1Tag tag)
	{
		return HasData && Asn1Tag.Decode(_remaining.Span, out _) == tag;
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
		AsnDecoder.ReadSequence(_remaining.Span, AsnEncodingRules.DER, out int offset, out int length, out int consumed, tag);
		element = Take(consumed);
		return new DerReader(element.Slice(offset, length));
	}

	public DerReader ReadSequence(Asn1Tag? tag = null)
	{
		return ReadSequence(out _, tag);
	}

	// A SET OF whose elements are in the order that DER requires.
	public DerReader ReadSetOf()
	{
		AsnDecoder.ReadSetOf(_remaining.Span, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
		return new DerReader(Take(consumed).Slice(offset, length));
	}

	// One value of any type, whole.
	public ReadOnlyMemory<byte> ReadEncodedValue()
	{
		AsnDecoder.ReadEncodedValue(_remaining.Span, AsnEncodingRules.DER, out _, out _, out int consumed);
		return Take(consumed);
	}

	public string ReadObjectIdentifier()
	{
		string value = AsnDecoder.ReadObjectIdentifier(_remaining.Span, AsnEncodingRules.DER, out int consumed);
		Take(consumed);
		return value;
	}

	// The contents of an INTEGER, which DER requires to be minimal.
	public ReadOnlyMemory<byte> ReadIntegerBytes()
	{
		ReadOnlySpan<byte> value = AsnDecoder.ReadIntegerBytes(_remaining.Span, AsnEncodingRules.DER, out int consumed);
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

	public bool ReadBoolean()
	{
		bool value = AsnDecoder.ReadBoolean(_remaining.Span, AsnEncodingRules.DER, out int consumed);
		Take(consumed);
		return value;
	}

	// The bits of a BIT STRING; wholeBytes rejects one with unused bits.
	public ReadOnlyMemory<byte> ReadBitString(Asn1Tag? tag = null, bool wholeBytes = true)
	{
		if (!AsnDecoder.TryReadPrimitiveBitString(_remaining.Span, AsnEncodingRules.DER, out int unusedBits, out ReadOnlySpan<byte> value, out int consumed, tag) || wholeBytes && unusedBits is not 0)
		{
			throw new AsnContentException();
		}

		return TakeContents(consumed, value.Length);
	}

	public ReadOnlyMemory<byte> ReadOctetString()
	{
		if (!AsnDecoder.TryReadPrimitiveOctetString(_remaining.Span, AsnEncodingRules.DER, out ReadOnlySpan<byte> value, out int consumed))
		{
			throw new AsnContentException();
		}

		return TakeContents(consumed, value.Length);
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
