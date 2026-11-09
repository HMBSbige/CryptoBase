using System.Formats.Asn1;

namespace CryptoBase.SM2;

// The DER of SM2Cipher, GB/T 35276-2017, Sec. 7.2 (GM/T 0009-2012): SEQUENCE { XCoordinate INTEGER, YCoordinate INTEGER, HASH OCTET STRING (SIZE(32)), CipherText OCTET STRING }, holding C1 = (x1, y1), C3 and C2. A ciphertext is public, so the encoding and parsing may branch on it.
internal static class SM2CipherDer
{
	private const byte SequenceTag = 0x30;
	private const byte OctetStringTag = 0x04;

	private const int CoordinateLength = 32;

	private const int HashLength = 32;

	// INTEGERs of 33 bytes, a coordinate with its sign byte, and HASH; the content of CipherText adds its own TLV.
	private const int MaxFixedLength = 2 * (2 + CoordinateLength + 1) + 2 + HashLength;

	// The longest SM2Cipher of a plaintext of plaintextLength bytes, or −1 if that exceeds int.MaxValue.
	internal static int GetMaxLength(int plaintextLength)
	{
		Debug.Assert(plaintextLength >= 0);

		long content = MaxFixedLength + KeyInfoDer.GetLongEncodedLength(plaintextLength);
		long total = KeyInfoDer.GetLongEncodedLength(content);
		return total <= int.MaxValue ? (int)total : -1;
	}

	// Writes the SM2Cipher of C1, an uncompressed point, and a C2 of plaintextLength bytes, but for the contents of HASH and CipherText, whose offsets it returns; returns the length. destination is at least GetMaxLength long.
	internal static int Write(ReadOnlySpan<byte> c1, int plaintextLength, Span<byte> destination, out int hashOffset, out int cipherTextOffset)
	{
		Debug.Assert(c1.Length is 1 + 2 * CoordinateLength && c1[0] is 0x04);

		ReadOnlySpan<byte> x = TrimLeadingZeros(c1.Slice(1, CoordinateLength));
		ReadOnlySpan<byte> y = TrimLeadingZeros(c1.Slice(1 + CoordinateLength, CoordinateLength));
		long content = GetIntegerLength(x) + GetIntegerLength(y) + 2 + HashLength + KeyInfoDer.GetLongEncodedLength(plaintextLength);
		int written = KeyInfoDer.WriteHeader(SequenceTag, (int)content, destination);
		written += KeyInfoDer.WriteInteger(x, destination.Slice(written));
		written += KeyInfoDer.WriteInteger(y, destination.Slice(written));
		written += KeyInfoDer.WriteHeader(OctetStringTag, HashLength, destination.Slice(written));
		hashOffset = written;
		written += HashLength;
		written += KeyInfoDer.WriteHeader(OctetStringTag, plaintextLength, destination.Slice(written));
		cipherTextOffset = written;
		return written + plaintextLength;
	}

	// Reads the SM2Cipher that fills source: c1 receives C1 as an uncompressed point, of coordinates not yet checked against the field, and hash and cipherText are slices of source. DER only: the INTEGERs must be minimal and not negative, and HASH must hold 32 bytes. The CipherText may be empty; the caller decides on that.
	internal static bool TryRead(ReadOnlySpan<byte> source, Span<byte> c1, out ReadOnlySpan<byte> hash, out ReadOnlySpan<byte> cipherText)
	{
		Debug.Assert(c1.Length is 1 + 2 * CoordinateLength);

		hash = default;
		cipherText = default;

		try
		{
			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out int offset, out int length, out int consumed);

			if (consumed != source.Length)
			{
				return false;
			}

			ReadOnlySpan<byte> contents = source.Slice(offset, length);
			ReadOnlySpan<byte> x = AsnDecoder.ReadIntegerBytes(contents, AsnEncodingRules.DER, out consumed);
			contents = contents.Slice(consumed);
			ReadOnlySpan<byte> y = AsnDecoder.ReadIntegerBytes(contents, AsnEncodingRules.DER, out consumed);
			contents = contents.Slice(consumed);

			if (!AsnDecoder.TryReadPrimitiveOctetString(contents, AsnEncodingRules.DER, out hash, out consumed) || hash.Length is not HashLength)
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!AsnDecoder.TryReadPrimitiveOctetString(contents, AsnEncodingRules.DER, out cipherText, out consumed) || consumed != contents.Length)
			{
				return false;
			}

			c1[0] = 0x04;
			return TryReadCoordinate(x, c1.Slice(1, CoordinateLength)) && TryReadCoordinate(y, c1.Slice(1 + CoordinateLength, CoordinateLength));
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// The contents of a minimal INTEGER, as DER rules ensured, that is not negative and fits in 32 bytes, written over the whole of destination.
	private static bool TryReadCoordinate(ReadOnlySpan<byte> contents, Span<byte> destination)
	{
		if (contents[0] >= 0x80)
		{
			return false;
		}

		ReadOnlySpan<byte> magnitude = contents is [0, _, ..] ? contents.Slice(1) : contents;

		if (magnitude.Length > CoordinateLength)
		{
			return false;
		}

		destination.Slice(0, CoordinateLength - magnitude.Length).Clear();
		magnitude.CopyTo(destination.Slice(CoordinateLength - magnitude.Length));
		return true;
	}

	// The minimal big-endian magnitude, a single 0 byte for 0.
	private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
	{
		int start = value.IndexOfAnyExcept((byte)0);
		return start < 0 ? value.Slice(value.Length - 1) : value.Slice(start);
	}

	private static int GetIntegerLength(ReadOnlySpan<byte> magnitude)
	{
		return 2 + magnitude.Length + (magnitude[0] >> 7);
	}
}
