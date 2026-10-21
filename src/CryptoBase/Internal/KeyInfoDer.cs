using System.Formats.Asn1;

namespace CryptoBase.Internal;

// The DER envelopes of keys: SubjectPublicKeyInfo (RFC 5280, Sec. 4.1) and PrivateKeyInfo or OneAsymmetricKey (RFC 5958), for one
// AlgorithmIdentifier given whole in DER, so that a key of another algorithm or with other parameters does not match.
internal static class KeyInfoDer
{
	private static readonly Asn1Tag AttributesTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag PublicKeyTag = new(TagClass.ContextSpecific, 1);

	// The length of a TLV with a one-byte tag around contentLength bytes.
	internal static int GetEncodedLength(int contentLength)
	{
		Debug.Assert(contentLength >= 0);

		int lengthLength = contentLength < 0x80 ? 1 : 1 + (39 - BitOperations.LeadingZeroCount((uint)contentLength)) / 8;
		return 1 + lengthLength + contentLength;
	}

	// SEQUENCE { algorithm, BIT STRING with no unused bits }.
	internal static int GetSubjectPublicKeyInfoLength(ReadOnlySpan<byte> algorithmIdentifier, int publicKeyLength)
	{
		return GetEncodedLength(algorithmIdentifier.Length + GetEncodedLength(1 + publicKeyLength));
	}

	// SEQUENCE { INTEGER 0, algorithm, OCTET STRING }.
	internal static int GetPrivateKeyInfoLength(ReadOnlySpan<byte> algorithmIdentifier, int privateKeyLength)
	{
		return GetEncodedLength(3 + algorithmIdentifier.Length + GetEncodedLength(privateKeyLength));
	}

	// destination is at least GetSubjectPublicKeyInfoLength long.
	internal static int WriteSubjectPublicKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> publicKey, Span<byte> destination)
	{
		AsnWriter writer = new(AsnEncodingRules.DER, GetSubjectPublicKeyInfoLength(algorithmIdentifier, publicKey.Length));

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(algorithmIdentifier);
			writer.WriteBitString(publicKey);
		}

		return writer.Encode(destination);
	}

	// A version 1 PrivateKeyInfo whose privateKey holds privateKey. destination is at least GetPrivateKeyInfoLength long. The writer erases its copy.
	internal static int WritePrivateKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> privateKey, Span<byte> destination)
	{
		AsnWriter writer = new(AsnEncodingRules.DER, GetPrivateKeyInfoLength(algorithmIdentifier, privateKey.Length));

		try
		{
			using (writer.PushSequence())
			{
				writer.WriteInteger(0);
				writer.WriteEncodedValue(algorithmIdentifier);
				writer.WriteOctetString(privateKey);
			}

			return writer.Encode(destination);
		}
		finally
		{
			writer.Reset();
		}
	}

	// The subjectPublicKey of the SubjectPublicKeyInfo that fills source.
	internal static bool TryReadSubjectPublicKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> source, out ReadOnlySpan<byte> publicKey)
	{
		publicKey = default;

		try
		{
			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
			ReadOnlySpan<byte> contents = source.Slice(offset, length);

			if (consumed != source.Length || !contents.StartsWith(algorithmIdentifier))
			{
				return false;
			}

			contents = contents.Slice(algorithmIdentifier.Length);

			return AsnDecoder.TryReadPrimitiveBitString(contents, AsnEncodingRules.DER, out int unusedBits, out publicKey, out consumed)
				&& unusedBits is 0
				&& consumed == contents.Length;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// The privateKey of the PrivateKeyInfo or OneAsymmetricKey that fills source, and the publicKey of a version 2
	// OneAsymmetricKey, or empty. Attributes are skipped. The results are slices of source.
	internal static bool TryReadPrivateKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> source, out ReadOnlySpan<byte> privateKey, out ReadOnlySpan<byte> publicKey)
	{
		privateKey = default;
		publicKey = default;

		try
		{
			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
			ReadOnlySpan<byte> contents = source.Slice(offset, length);

			if (consumed != source.Length || !AsnDecoder.TryReadInt32(contents, AsnEncodingRules.DER, out int version, out consumed) || version is not (0 or 1))
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!contents.StartsWith(algorithmIdentifier))
			{
				return false;
			}

			contents = contents.Slice(algorithmIdentifier.Length);

			if (!AsnDecoder.TryReadPrimitiveOctetString(contents, AsnEncodingRules.DER, out privateKey, out consumed))
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!contents.IsEmpty && Asn1Tag.Decode(contents, out _) == AttributesTag)
			{
				AsnDecoder.ReadEncodedValue(contents, AsnEncodingRules.DER, out _, out _, out consumed);
				contents = contents.Slice(consumed);
			}

			// Empty means absent, so an empty publicKey is invalid.
			if (version is 1 && !contents.IsEmpty)
			{
				if (!AsnDecoder.TryReadPrimitiveBitString(contents, AsnEncodingRules.DER, out int unusedBits, out publicKey, out consumed, PublicKeyTag) || unusedBits is not 0 || publicKey.IsEmpty)
				{
					return false;
				}

				contents = contents.Slice(consumed);
			}

			return contents.IsEmpty;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}
}
