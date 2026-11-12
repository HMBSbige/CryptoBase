#if !NET11_0_OR_GREATER
namespace System.Formats.Asn1;

// The members in use of the reader that .NET 11 defines, with the same results and errors.
internal ref struct ValueAsnReader(ReadOnlySpan<byte> source, AsnEncodingRules ruleSet)
{
	private ReadOnlySpan<byte> _remaining = source;

	public readonly bool HasData => !_remaining.IsEmpty;

	public readonly void ThrowIfNotEmpty()
	{
		if (HasData)
		{
			throw new AsnContentException();
		}
	}

	public readonly Asn1Tag PeekTag()
	{
		return Asn1Tag.Decode(_remaining, out _);
	}

	public readonly ReadOnlySpan<byte> PeekEncodedValue()
	{
		AsnDecoder.ReadEncodedValue(_remaining, ruleSet, out _, out _, out int consumed);
		return _remaining.Slice(0, consumed);
	}

	public readonly ReadOnlySpan<byte> PeekContentBytes()
	{
		AsnDecoder.ReadEncodedValue(_remaining, ruleSet, out int offset, out int length, out _);
		return _remaining.Slice(offset, length);
	}

	public ReadOnlySpan<byte> ReadEncodedValue()
	{
		AsnDecoder.ReadEncodedValue(_remaining, ruleSet, out _, out _, out int consumed);
		return Take(consumed);
	}

	public ValueAsnReader ReadSequence(Asn1Tag? expectedTag = null)
	{
		AsnDecoder.ReadSequence(_remaining, ruleSet, out int offset, out int length, out int consumed, expectedTag);
		return new ValueAsnReader(Take(consumed).Slice(offset, length), ruleSet);
	}

	public ValueAsnReader ReadSetOf(Asn1Tag? expectedTag = null)
	{
		AsnDecoder.ReadSetOf(_remaining, ruleSet, out int offset, out int length, out int consumed, expectedTag: expectedTag);
		return new ValueAsnReader(Take(consumed).Slice(offset, length), ruleSet);
	}

	public string ReadObjectIdentifier(Asn1Tag? expectedTag = null)
	{
		string value = AsnDecoder.ReadObjectIdentifier(_remaining, ruleSet, out int consumed, expectedTag);
		Take(consumed);
		return value;
	}

	public ReadOnlySpan<byte> ReadIntegerBytes(Asn1Tag? expectedTag = null)
	{
		ReadOnlySpan<byte> value = AsnDecoder.ReadIntegerBytes(_remaining, ruleSet, out int consumed, expectedTag);
		Take(consumed);
		return value;
	}

	public bool TryReadInt32(out int value, Asn1Tag? expectedTag = null)
	{
		bool read = AsnDecoder.TryReadInt32(_remaining, ruleSet, out value, out int consumed, expectedTag);
		Take(consumed);
		return read;
	}

	public bool TryReadPrimitiveBitString(out int unusedBitCount, out ReadOnlySpan<byte> value, Asn1Tag? expectedTag = null)
	{
		bool read = AsnDecoder.TryReadPrimitiveBitString(_remaining, ruleSet, out unusedBitCount, out value, out int consumed, expectedTag);
		Take(consumed);
		return read;
	}

	public bool TryReadPrimitiveOctetString(out ReadOnlySpan<byte> contents, Asn1Tag? expectedTag = null)
	{
		bool read = AsnDecoder.TryReadPrimitiveOctetString(_remaining, ruleSet, out contents, out int consumed, expectedTag);
		Take(consumed);
		return read;
	}

	public string ReadCharacterString(UniversalTagNumber encodingType, Asn1Tag? expectedTag = null)
	{
		string value = AsnDecoder.ReadCharacterString(_remaining, ruleSet, encodingType, out int consumed, expectedTag);
		Take(consumed);
		return value;
	}

	public DateTimeOffset ReadUtcTime(Asn1Tag? expectedTag = null)
	{
		DateTimeOffset value = AsnDecoder.ReadUtcTime(_remaining, ruleSet, out int consumed, expectedTag: expectedTag);
		Take(consumed);
		return value;
	}

	public DateTimeOffset ReadGeneralizedTime(Asn1Tag? expectedTag = null)
	{
		DateTimeOffset value = AsnDecoder.ReadGeneralizedTime(_remaining, ruleSet, out int consumed, expectedTag);
		Take(consumed);
		return value;
	}

	private ReadOnlySpan<byte> Take(int length)
	{
		ReadOnlySpan<byte> value = _remaining.Slice(0, length);
		_remaining = _remaining.Slice(length);
		return value;
	}
}
#endif
