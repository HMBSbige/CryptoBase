using CryptoBase.EllipticCurves.SM9;
using System.Formats.Asn1;

namespace CryptoBase.SM9;

// The DER of GB/T 41389-2022 (GM/T 0080-2020), Sec. 6.1.4 and 6.1.5: SM9Signature ::= SEQUENCE { H OCTET STRING, S BIT STRING } and SM9Cipher ::= SEQUENCE { EnType INTEGER, C1 BIT STRING, C3 OCTET STRING, C2 OCTET STRING }, with the points S and C1 uncompressed, 04 ‖ x ‖ y, in BIT STRINGs without unused bits, H and C3 of 32 bytes, and EnType 0, for C2 = M ⊕ K1. Signatures and ciphertexts are public, so the encoding and parsing may branch on them.
internal static class SM9Der
{
	private const byte SequenceTag = 0x30;
	private const byte OctetStringTag = 0x04;

	private const int HashLength = 32;

	// 30 66 04 20 h 03 42 00 S: the encoding has no other length.
	internal const int SignatureLength = 4 + HashLength + 3 + SM9G1.EncodedLength;

	// INTEGER 0, C1 and C3; C2 adds its own TLV.
	private const int CipherFixedLength = 3 + 3 + SM9G1.EncodedLength + 2 + HashLength;

	private static ReadOnlySpan<byte> SignaturePrefix => [SequenceTag, SignatureLength - 2, OctetStringTag, HashLength];

	private static ReadOnlySpan<byte> PointPrefix => [0x03, 1 + SM9G1.EncodedLength, 0x00];

	private static ReadOnlySpan<byte> EnTypePrefix => [0x02, 0x01, 0x00];

	internal static void WriteSignature(ReadOnlySpan<byte> h, ReadOnlySpan<byte> s, Span<byte> destination)
	{
		Debug.Assert(h.Length is HashLength && s.Length is SM9G1.EncodedLength && destination.Length >= SignatureLength);

		SignaturePrefix.CopyTo(destination);
		h.CopyTo(destination.Slice(SignaturePrefix.Length));
		PointPrefix.CopyTo(destination.Slice(SignaturePrefix.Length + HashLength));
		s.CopyTo(destination.Slice(SignatureLength - SM9G1.EncodedLength));
	}

	// h and S as slices of source, which must be the DER of an SM9Signature and nothing else. S is not yet checked against the curve.
	internal static bool TryReadSignature(ReadOnlySpan<byte> source, out ReadOnlySpan<byte> h, out ReadOnlySpan<byte> s)
	{
		if (source.Length is not SignatureLength || !source.StartsWith(SignaturePrefix) || !source.Slice(SignaturePrefix.Length + HashLength).StartsWith(PointPrefix))
		{
			h = default;
			s = default;
			return false;
		}

		h = source.Slice(SignaturePrefix.Length, HashLength);
		s = source.Slice(SignatureLength - SM9G1.EncodedLength);
		return true;
	}

	// The length of the SM9Cipher of a plaintext of plaintextLength bytes, or −1 if that exceeds int.MaxValue.
	internal static int GetCipherLength(int plaintextLength)
	{
		Debug.Assert(plaintextLength >= 0);

		long total = KeyInfoDer.GetLongEncodedLength(CipherFixedLength + KeyInfoDer.GetLongEncodedLength(plaintextLength));
		return total <= int.MaxValue ? (int)total : -1;
	}

	// Writes the SM9Cipher of C1, an uncompressed point, and a C2 of plaintextLength bytes, but for the contents of C3 and C2, whose offsets it returns; returns the length. destination is at least GetCipherLength long.
	internal static int WriteCipher(ReadOnlySpan<byte> c1, int plaintextLength, Span<byte> destination, out int hashOffset, out int cipherTextOffset)
	{
		Debug.Assert(c1.Length is SM9G1.EncodedLength && c1[0] is 0x04);

		int written = KeyInfoDer.WriteHeader(SequenceTag, (int)(CipherFixedLength + KeyInfoDer.GetLongEncodedLength(plaintextLength)), destination);
		EnTypePrefix.CopyTo(destination.Slice(written));
		written += EnTypePrefix.Length;
		PointPrefix.CopyTo(destination.Slice(written));
		written += PointPrefix.Length;
		c1.CopyTo(destination.Slice(written));
		written += c1.Length;
		written += KeyInfoDer.WriteHeader(OctetStringTag, HashLength, destination.Slice(written));
		hashOffset = written;
		written += HashLength;
		written += KeyInfoDer.WriteHeader(OctetStringTag, plaintextLength, destination.Slice(written));
		cipherTextOffset = written;
		return written + plaintextLength;
	}

	// Reads the SM9Cipher that fills source, DER only: c1 is the content of the BIT STRING, of 65 bytes, whose point is not yet checked, and C3 must hold 32 bytes. EnType must be 0. C2 may be empty; the caller decides on that.
	internal static bool TryReadCipher(ReadOnlySpan<byte> source, out ReadOnlySpan<byte> c1, out ReadOnlySpan<byte> c3, out ReadOnlySpan<byte> c2)
	{
		c1 = default;
		c3 = default;
		c2 = default;

		try
		{
			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out int offset, out int length, out int consumed);

			if (consumed != source.Length)
			{
				return false;
			}

			ReadOnlySpan<byte> contents = source.Slice(offset, length);

			if (!AsnDecoder.TryReadInt32(contents, AsnEncodingRules.DER, out int enType, out consumed) || enType is not 0)
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!AsnDecoder.TryReadPrimitiveBitString(contents, AsnEncodingRules.DER, out int unusedBitCount, out c1, out consumed) || unusedBitCount is not 0 || c1.Length is not SM9G1.EncodedLength)
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!AsnDecoder.TryReadPrimitiveOctetString(contents, AsnEncodingRules.DER, out c3, out consumed) || c3.Length is not HashLength)
			{
				return false;
			}

			contents = contents.Slice(consumed);
			return AsnDecoder.TryReadPrimitiveOctetString(contents, AsnEncodingRules.DER, out c2, out consumed) && consumed == contents.Length;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}
}
