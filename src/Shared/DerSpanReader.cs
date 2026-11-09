using System.Formats.Asn1;

namespace CryptoBase.Internal;

// Reads DER values in order, as slices of the source. Malformed input throws AsnContentException.
internal ref struct DerSpanReader(ReadOnlySpan<byte> source)
{
	private ReadOnlySpan<byte> _remaining = source;

	public readonly bool HasData => !_remaining.IsEmpty;

	public readonly bool PeekTagIs(Asn1Tag tag)
	{
		return HasData && Asn1Tag.Decode(_remaining, out _) == tag;
	}

	public readonly void ThrowIfNotEmpty()
	{
		if (HasData)
		{
			throw new AsnContentException();
		}
	}

	// A SEQUENCE, or the constructed value with tag; returns a reader of its contents.
	public DerSpanReader ReadSequence(Asn1Tag? tag = null)
	{
		AsnDecoder.ReadSequence(_remaining, AsnEncodingRules.DER, out int offset, out int length, out int consumed, tag);
		DerSpanReader contents = new(_remaining.Slice(offset, length));
		_remaining = _remaining.Slice(consumed);
		return contents;
	}

	// A SEQUENCE, whole.
	public ReadOnlySpan<byte> ReadEncodedSequence()
	{
		AsnDecoder.ReadSequence(_remaining, AsnEncodingRules.DER, out _, out _, out int consumed);
		return Take(consumed);
	}

	// One value of any type, whole.
	public ReadOnlySpan<byte> ReadEncodedValue()
	{
		AsnDecoder.ReadEncodedValue(_remaining, AsnEncodingRules.DER, out _, out _, out int consumed);
		return Take(consumed);
	}

	public string ReadObjectIdentifier()
	{
		string value = AsnDecoder.ReadObjectIdentifier(_remaining, AsnEncodingRules.DER, out int consumed);
		Take(consumed);
		return value;
	}

	public int ReadInt32()
	{
		if (!AsnDecoder.TryReadInt32(_remaining, AsnEncodingRules.DER, out int value, out int consumed))
		{
			throw new AsnContentException();
		}

		Take(consumed);
		return value;
	}

	// The contents of an INTEGER that is not negative, which DER requires to be minimal.
	public ReadOnlySpan<byte> ReadUnsignedInteger()
	{
		ReadOnlySpan<byte> value = AsnDecoder.ReadIntegerBytes(_remaining, AsnEncodingRules.DER, out int consumed);

		if (value[0] >= 0x80)
		{
			throw new AsnContentException();
		}

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
