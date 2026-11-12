namespace CryptoBase.Internal;

// The DER envelopes of keys: SubjectPublicKeyInfo (RFC 5280, Sec. 4.1) and PrivateKeyInfo or OneAsymmetricKey (RFC 5958), for one AlgorithmIdentifier given whole in DER, so that a key of another algorithm or with other parameters does not match.
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

	// The length of a TLV with a one-byte tag around contentLength bytes, which may exceed int.MaxValue.
	internal static long GetLongEncodedLength(long contentLength)
	{
		int lengthLength = contentLength < 0x80 ? 1 : 1 + (71 - BitOperations.LeadingZeroCount((ulong)contentLength)) / 8;
		return 1 + lengthLength + contentLength;
	}

	internal static int WriteHeader(byte tag, int length, Span<byte> destination)
	{
		destination[0] = tag;

		if (length < 0x80)
		{
			destination[1] = (byte)length;
			return 2;
		}

		int lengthLength = (39 - BitOperations.LeadingZeroCount((uint)length)) / 8;
		destination[1] = (byte)(0x80 | lengthLength);

		for (int i = lengthLength; i > 0; --i)
		{
			destination[1 + i] = (byte)length;
			length >>= 8;
		}

		return 2 + lengthLength;
	}

	// The INTEGER of a minimal positive magnitude of fewer than 127 bytes, whose length takes one byte.
	internal static int WriteInteger(ReadOnlySpan<byte> magnitude, Span<byte> destination)
	{
		Debug.Assert(magnitude.Length < 0x7F);

		int padding = magnitude[0] >> 7;
		destination[0] = 0x02;
		destination[1] = (byte)(padding + magnitude.Length);
		destination[2] = 0;
		magnitude.CopyTo(destination.Slice(2 + padding));
		return 2 + padding + magnitude.Length;
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
			ValueAsnReader reader = new(source, AsnEncodingRules.DER);
			ValueAsnReader contents = reader.ReadSequence();

			return !reader.HasData
				&& contents.ReadEncodedValue().SequenceEqual(algorithmIdentifier)
				&& contents.TryReadPrimitiveBitString(out int unusedBits, out publicKey)
				&& unusedBits is 0
				&& !contents.HasData;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// The privateKey of the PrivateKeyInfo or OneAsymmetricKey that fills source, and the publicKey of a version 2 OneAsymmetricKey, or empty. Attributes are skipped. The results are slices of source.
	internal static bool TryReadPrivateKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> source, out ReadOnlySpan<byte> privateKey, out ReadOnlySpan<byte> publicKey)
	{
		privateKey = default;
		publicKey = default;

		try
		{
			ValueAsnReader reader = new(source, AsnEncodingRules.DER);
			ValueAsnReader contents = reader.ReadSequence();

			if (reader.HasData || !contents.TryReadInt32(out int version) || version is not (0 or 1))
			{
				return false;
			}

			if (!contents.ReadEncodedValue().SequenceEqual(algorithmIdentifier) || !contents.TryReadPrimitiveOctetString(out privateKey))
			{
				return false;
			}

			if (contents.PeekTagIs(AttributesTag))
			{
				SkipAttributes(ref contents);
			}

			// Empty means absent, so an empty publicKey is invalid.
			if (version is 1 && contents.HasData && (!contents.TryReadPrimitiveBitString(out int unusedBits, out publicKey, PublicKeyTag) || unusedBits is not 0 || publicKey.IsEmpty))
			{
				return false;
			}

			return !contents.HasData;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// SET OF SEQUENCE { OBJECT IDENTIFIER, SET OF ANY } in DER; the values, of unknown types, are skipped whole.
	private static void SkipAttributes(ref ValueAsnReader reader)
	{
		ValueAsnReader attributes = reader.ReadSetOf(AttributesTag);

		while (attributes.HasData)
		{
			ValueAsnReader attribute = attributes.ReadSequence();
			attribute.ReadObjectIdentifier();
			ValueAsnReader values = attribute.ReadSetOf();
			attribute.ThrowIfNotEmpty();

			while (values.HasData)
			{
				values.ReadEncodedValue();
			}
		}
	}
}
