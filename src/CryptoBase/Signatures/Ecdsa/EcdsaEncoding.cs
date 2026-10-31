using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Ecdsa;

// The integer methods do not branch on or index by their input, which may be secret; signatures are public, so their encoding and parsing may branch.
internal static class EcdsaEncoding<TOrder> where TOrder : unmanaged, IMontgomeryModulus
{
	private const byte SequenceTag = 0x30;
	private const byte IntegerTag = 0x02;

	// A value below 2^BitLength takes at most BitLength / 8 + 1 bytes as an INTEGER, the sign bit included.
	internal static int MaxDerLength => KeyInfoDer.GetEncodedLength(2 * KeyInfoDer.GetEncodedLength(TOrder.BitLength / 8 + 1));

	// Takes the leftmost BitLength bits of value, or all of value if it is shorter.
	internal static void Truncate(ReadOnlySpan<byte> value, Span<byte> destination)
	{
		int length = TOrder.ByteLength;
		Debug.Assert(destination.Length == length && !value.Overlaps(destination));

		if (value.Length < length)
		{
			destination.Slice(0, length - value.Length).Clear();
			value.CopyTo(destination.Slice(length - value.Length));
			return;
		}

		value.Slice(0, length).CopyTo(destination);
		int shift = 8 * length - TOrder.BitLength;

		if (shift is 0)
		{
			return;
		}

		for (int i = length - 1; i > 0; --i)
		{
			destination[i] = (byte)(destination[i] >> shift | destination[i - 1] << 8 - shift);
		}

		destination[0] >>= shift;
	}

	[SkipLocalsInit]
	internal static void ImportHash(ReadOnlySpan<byte> hash, out FieldElement<TOrder> result)
	{
		Span<byte> value = stackalloc byte[TOrder.ByteLength];
		Truncate(hash, value);
		FieldElement<TOrder>.ImportReduced(value, out result);
	}

	// r and s lie in [1, n − 1], and destination is at least MaxDerLength long.
	[SkipLocalsInit]
	internal static int Write(in FieldElement<TOrder> r, in FieldElement<TOrder> s, Span<byte> destination)
	{
		int length = TOrder.ByteLength;
		Span<byte> values = stackalloc byte[2 * length];
		FieldElement<TOrder>.Export(in r, values.Slice(0, length));
		FieldElement<TOrder>.Export(in s, values.Slice(length));
		ReadOnlySpan<byte> rMagnitude = TrimLeadingZeros(values.Slice(0, length));
		ReadOnlySpan<byte> sMagnitude = TrimLeadingZeros(values.Slice(length));
		int contentLength = GetIntegerLength(rMagnitude) + GetIntegerLength(sMagnitude);
		int written = WriteHeader(SequenceTag, contentLength, destination);
		written += WriteInteger(rMagnitude, destination.Slice(written));
		written += WriteInteger(sMagnitude, destination.Slice(written));
		return written;
	}

	// The value has a nonzero byte.
	private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
	{
		return value.Slice(value.IndexOfAnyExcept((byte)0));
	}

	private static int GetIntegerLength(ReadOnlySpan<byte> magnitude)
	{
		return KeyInfoDer.GetEncodedLength(magnitude.Length + (magnitude[0] >> 7));
	}

	private static int WriteInteger(ReadOnlySpan<byte> magnitude, Span<byte> destination)
	{
		int padding = magnitude[0] >> 7;
		int written = WriteHeader(IntegerTag, padding + magnitude.Length, destination);

		if (padding is not 0)
		{
			destination[written++] = 0;
		}

		magnitude.CopyTo(destination.Slice(written));
		return written + magnitude.Length;
	}

	// No content of a signature reaches 256 bytes, so a long length takes one byte.
	private static int WriteHeader(byte tag, int length, Span<byte> destination)
	{
		Debug.Assert(length < 0x100);

		destination[0] = tag;

		if (length < 0x80)
		{
			destination[1] = (byte)length;
			return 2;
		}

		destination[1] = 0x81;
		destination[2] = (byte)length;
		return 3;
	}

	internal static bool TryRead(ReadOnlySpan<byte> signature, out FieldElement<TOrder> r, out FieldElement<TOrder> s)
	{
		s = default;

		if (!TryReadElement(signature, SequenceTag, out ReadOnlySpan<byte> contents, out int consumed) || consumed != signature.Length)
		{
			r = default;
			return false;
		}

		return TryReadInteger(ref contents, out r) && TryReadInteger(ref contents, out s) && contents.IsEmpty;
	}

	// A signature has no content of 256 bytes or more, so a length of more than one byte is invalid whatever its value.
	private static bool TryReadElement(ReadOnlySpan<byte> source, byte tag, out ReadOnlySpan<byte> contents, out int consumed)
	{
		contents = default;
		consumed = 0;

		if (source is not [var first, var length, ..] || first != tag)
		{
			return false;
		}

		int headerLength = 2;

		if (length >= 0x80)
		{
			if (length is not 0x81 || source is not [_, _, >= 0x80 and var longLength, ..])
			{
				return false;
			}

			length = longLength;
			headerLength = 3;
		}

		if (source.Length - headerLength < length)
		{
			return false;
		}

		contents = source.Slice(headerLength, length);
		consumed = headerLength + length;
		return true;
	}

	[SkipLocalsInit]
	private static bool TryReadInteger(ref ReadOnlySpan<byte> source, out FieldElement<TOrder> value)
	{
		value = default;

		if (!TryReadElement(source, IntegerTag, out ReadOnlySpan<byte> contents, out int consumed) || contents is [] or [>= 0x80, ..] or [0, < 0x80, ..])
		{
			return false;
		}

		ReadOnlySpan<byte> magnitude = contents is [0, ..] ? contents.Slice(1) : contents;
		int length = TOrder.ByteLength;

		if (magnitude.Length > length)
		{
			return false;
		}

		Span<byte> buffer = stackalloc byte[length];
		buffer.Slice(0, length - magnitude.Length).Clear();
		magnitude.CopyTo(buffer.Slice(length - magnitude.Length));
		source = source.Slice(consumed);
		return FieldElement<TOrder>.TryImportNonzero(buffer, out value);
	}
}
