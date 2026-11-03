using System.Formats.Asn1;

namespace CryptoBase.Signatures.Rsa;

// The DER encodings of RSA keys: RSAPublicKey and RSAPrivateKey (RFC 8017, Appendices A.1.1 and A.1.2), and the AlgorithmIdentifiers that SubjectPublicKeyInfo and PKCS #8 carry them with (RFC 4055).
// Readers return slices of their source and throw ArgumentException for the parameter source, or NotSupportedException for a valid key or identifier that is not supported.
internal static class RsaKeyDer
{
	private const string RsassaPssOid = "1.2.840.113549.1.1.10";
	private const string Mgf1Oid = "1.2.840.113549.1.1.8";
	private const string SourceName = "source";

	// The length of INTEGER 0, the version of RSAPrivateKey.
	private const int VersionLength = 3;

	private static readonly Asn1Tag HashAlgorithmTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag MaskGenAlgorithmTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag SaltLengthTag = new(TagClass.ContextSpecific, 2, true);
	private static readonly Asn1Tag TrailerFieldTag = new(TagClass.ContextSpecific, 3, true);

	private static readonly RsaPrivateComponent[] PrivateComponents =
	[
		RsaPrivateComponent.PrivateExponent, RsaPrivateComponent.Prime1, RsaPrivateComponent.Prime2, RsaPrivateComponent.Exponent1, RsaPrivateComponent.Exponent2, RsaPrivateComponent.Coefficient
	];

	// rsaEncryption with the NULL parameters that RFC 4055, Sec. 1.2, requires.
	internal static ReadOnlySpan<byte> RsaEncryption => [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];

	// Whether an AlgorithmIdentifier has the OID id-RSASSA-PSS, whatever its parameters.
	internal static bool IsRsassaPss(ReadOnlySpan<byte> algorithmIdentifier)
	{
		try
		{
			DerSpanReader reader = new(algorithmIdentifier);
			return reader.ReadSequence().ReadObjectIdentifier() is RsassaPssOid;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// The AlgorithmIdentifier of the SubjectPublicKeyInfo, or of the PrivateKeyInfo if privateKey is set, that fills source, which KeyInfoDer then checks whole.
	internal static ReadOnlySpan<byte> ReadKeyInfoAlgorithm(ReadOnlySpan<byte> source, bool privateKey)
	{
		try
		{
			DerSpanReader reader = new(source);
			DerSpanReader contents = reader.ReadSequence();
			reader.ThrowIfNotEmpty();

			if (privateKey)
			{
				contents.ReadEncodedValue();
			}

			return contents.ReadEncodedSequence();
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The key encoding is invalid.", SourceName, e);
		}
	}

	// The algorithms, as RsaAlgorithms bits, that an AlgorithmIdentifier of a key allows whatever the modulus (RFC 4055, Sec. 3.3): rsaEncryption with NULL parameters allows each one, and id-RSASSA-PSS
	// RSASSA-PSS alone, with each hash if the parameters are absent, and otherwise with the hash that RSASSA-PSS-params allow.
	internal static int GetAllowedAlgorithms(ReadOnlySpan<byte> algorithmIdentifier)
	{
		if (algorithmIdentifier.SequenceEqual(RsaEncryption))
		{
			return RsaAlgorithms.All;
		}

		bool allowed;
		SignatureAlgorithm algorithm;

		try
		{
			DerSpanReader reader = new(algorithmIdentifier);
			DerSpanReader contents = reader.ReadSequence();
			reader.ThrowIfNotEmpty();

			if (contents.ReadObjectIdentifier() is not RsassaPssOid)
			{
				throw new ArgumentException("The key is not an RSA key with valid parameters.", SourceName);
			}

			if (!contents.HasData)
			{
				return RsaAlgorithms.Pss;
			}

			ReadOnlySpan<byte> parameters = contents.ReadEncodedValue();
			contents.ThrowIfNotEmpty();
			allowed = TryReadPssParameters(parameters, out algorithm);
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The key encoding is invalid.", SourceName, e);
		}

		return allowed ? RsaAlgorithms.Bit(algorithm) : throw new NotSupportedException("The RSASSA-PSS parameters of the key allow none of the signature algorithms.");
	}

	// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }, whose INTEGERs are positive, filling source.
	internal static RsaPublicOperation ReadRsaPublicKey(ReadOnlySpan<byte> source)
	{
		ReadOnlySpan<byte> modulus;
		ReadOnlySpan<byte> exponent;

		try
		{
			DerSpanReader reader = new(source);
			DerSpanReader sequence = reader.ReadSequence();
			reader.ThrowIfNotEmpty();
			modulus = sequence.ReadUnsignedInteger();
			exponent = sequence.ReadUnsignedInteger();
			sequence.ThrowIfNotEmpty();
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The RSA public key is invalid.", SourceName, e);
		}

		return CreatePublicKey(modulus, exponent);
	}

	// RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient, otherPrimeInfos OPTIONAL }, filling source: version 0 with two primes,
	// as version 1 means more (RFC 8017, Appendix A.1.2), and positive INTEGERs. The key validates the values and copies them.
	internal static RsaPrivateOperation ReadRsaPrivateKey(ReadOnlySpan<byte> source)
	{
		ReadOnlySpan<byte> modulus, exponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient;

		try
		{
			DerSpanReader reader = new(source);
			DerSpanReader sequence = reader.ReadSequence();
			reader.ThrowIfNotEmpty();

			int version = sequence.ReadInt32();

			if (version is 1)
			{
				throw new NotSupportedException("Multi-prime RSA keys are not supported.");
			}

			if (version is not 0)
			{
				throw new AsnContentException();
			}

			modulus = sequence.ReadUnsignedInteger();
			exponent = sequence.ReadUnsignedInteger();
			privateExponent = sequence.ReadUnsignedInteger();
			prime1 = sequence.ReadUnsignedInteger();
			prime2 = sequence.ReadUnsignedInteger();
			exponent1 = sequence.ReadUnsignedInteger();
			exponent2 = sequence.ReadUnsignedInteger();
			coefficient = sequence.ReadUnsignedInteger();
			sequence.ThrowIfNotEmpty();
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The RSA private key is invalid.", SourceName, e);
		}

		RsaPublicOperation publicKey = CreatePublicKey(modulus, exponent);

		try
		{
			return RsaPrivateOperation.Create(publicKey, privateExponent, prime1, prime2, exponent1, exponent2, coefficient);
		}
		catch (ArgumentException e)
		{
			throw new ArgumentException("The RSA private key is invalid.", SourceName, e);
		}
	}

	internal static int GetRsaPublicKeyLength(RsaPublicOperation key)
	{
		return KeyInfoDer.GetEncodedLength(GetModulusIntegerLength(key) + GetExponentIntegerLength(key));
	}

	// destination is at least GetRsaPublicKeyLength long.
	[SkipLocalsInit]
	internal static int WriteRsaPublicKey(RsaPublicOperation key, Span<byte> destination)
	{
		int offset = WriteHeader(0x30, GetModulusIntegerLength(key) + GetExponentIntegerLength(key), destination);
		offset += WriteModulus(key, destination.Slice(offset));
		offset += WriteExponent(key, destination.Slice(offset));
		return offset;
	}

	// The components of RSAPrivateKey that need a zero byte before them to stay positive, as bits by the RsaPrivateComponent value; the copy that this takes of each is erased.
	[SkipLocalsInit]
	internal static int GetPaddedComponents(RsaPrivateOperation key)
	{
		int padded = 0;
		int maxLength = 0;

		foreach (RsaPrivateComponent component in PrivateComponents)
		{
			maxLength = Math.Max(maxLength, key.GetLength(component));
		}

		using CryptoBuffer<byte> value = new(stackalloc byte[maxLength]);

		foreach (RsaPrivateComponent component in PrivateComponents)
		{
			Span<byte> span = value.Span.Slice(0, key.GetLength(component));
			key.Write(component, span);
			padded |= span[0] >> 7 << (int)component;
		}

		return padded;
	}

	// The length of RSAPrivateKey, whose padded components are those of GetPaddedComponents.
	internal static int GetRsaPrivateKeyLength(RsaPrivateOperation key, int paddedComponents)
	{
		return KeyInfoDer.GetEncodedLength(GetRsaPrivateKeyContentLength(key, paddedComponents));
	}

	// destination is at least GetRsaPrivateKeyLength long, and receives the private values directly.
	internal static int WriteRsaPrivateKey(RsaPrivateOperation key, int paddedComponents, Span<byte> destination)
	{
		RsaPublicOperation publicKey = key.PublicKey;
		int offset = WriteHeader(0x30, GetRsaPrivateKeyContentLength(key, paddedComponents), destination);
		destination[offset++] = 0x02;
		destination[offset++] = 0x01;
		destination[offset++] = 0x00;
		offset += WriteModulus(publicKey, destination.Slice(offset));
		offset += WriteExponent(publicKey, destination.Slice(offset));

		foreach (RsaPrivateComponent component in PrivateComponents)
		{
			int length = key.GetLength(component);
			bool padded = IsPadded(paddedComponents, component);
			offset += WriteIntegerHeader(length, padded, destination.Slice(offset));
			key.Write(component, destination.Slice(offset, length));
			offset += length;
		}

		return offset;
	}

	private static RsaPublicOperation CreatePublicKey(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
	{
		try
		{
			return RsaPublicOperation.Create(modulus, exponent);
		}
		catch (ArgumentException e)
		{
			throw new ArgumentException("The RSA public key is invalid.", SourceName, e);
		}
	}

	// RSASSA-PSS-params (RFC 4055, Sec. 3.1) give algorithm if the hash is SHA-256, SHA-384 or SHA-512, MGF1 has the same hash, each hash AlgorithmIdentifier has NULL or absent parameters (Sec. 2.1),
	// the saltLength is at most the length of the hash, and the trailer field is 1. A field that holds its default value is accepted, as Sec. 3.1 requires of the trailer field, so that keys read the
	// parameters as CryptoBase.X509 does. Throws AsnContentException if the parameters are otherwise not DER.
	private static bool TryReadPssParameters(ReadOnlySpan<byte> parameters, out SignatureAlgorithm algorithm)
	{
		DerSpanReader reader = new(parameters);
		DerSpanReader fields = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		(algorithm, int hashLength) = (default, 0);
		(SignatureAlgorithm maskAlgorithm, int saltLength, int trailerField) = (default, 20, 1);

		if (fields.PeekTagIs(HashAlgorithmTag))
		{
			DerSpanReader field = fields.ReadSequence(HashAlgorithmTag);
			(algorithm, hashLength) = ReadHashAlgorithm(ref field);
			field.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(MaskGenAlgorithmTag))
		{
			DerSpanReader field = fields.ReadSequence(MaskGenAlgorithmTag);
			DerSpanReader maskGenAlgorithm = field.ReadSequence();
			field.ThrowIfNotEmpty();

			if (maskGenAlgorithm.ReadObjectIdentifier() is Mgf1Oid)
			{
				(maskAlgorithm, _) = ReadHashAlgorithm(ref maskGenAlgorithm);
			}
			else if (maskGenAlgorithm.HasData)
			{
				maskGenAlgorithm.ReadEncodedValue();
			}

			maskGenAlgorithm.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(SaltLengthTag))
		{
			DerSpanReader field = fields.ReadSequence(SaltLengthTag);
			saltLength = field.ReadInt32();
			field.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(TrailerFieldTag))
		{
			DerSpanReader field = fields.ReadSequence(TrailerFieldTag);
			trailerField = field.ReadInt32();
			field.ThrowIfNotEmpty();
		}

		fields.ThrowIfNotEmpty();
		return algorithm is not default(SignatureAlgorithm) && maskAlgorithm == algorithm && saltLength >= 0 && saltLength <= hashLength && trailerField is 1;
	}

	// A hash AlgorithmIdentifier, as the RSASSA-PSS algorithm of the hash and its length, or default for another hash or parameters other than NULL.
	private static (SignatureAlgorithm Algorithm, int HashLength) ReadHashAlgorithm(ref DerSpanReader reader)
	{
		DerSpanReader contents = reader.ReadSequence();
		string oid = contents.ReadObjectIdentifier();
		ReadOnlySpan<byte> parameters = contents.HasData ? contents.ReadEncodedValue() : default;
		contents.ThrowIfNotEmpty();

		if (parameters is not ([] or [0x05, 0x00]))
		{
			return default;
		}

		return oid switch
		{
			"2.16.840.1.101.3.4.2.1" => (SignatureAlgorithm.RsaPssSha256, 32),
			"2.16.840.1.101.3.4.2.2" => (SignatureAlgorithm.RsaPssSha384, 48),
			"2.16.840.1.101.3.4.2.3" => (SignatureAlgorithm.RsaPssSha512, 64),
			_ => default
		};
	}

	private static int GetRsaPrivateKeyContentLength(RsaPrivateOperation key, int paddedComponents)
	{
		int length = VersionLength + GetModulusIntegerLength(key.PublicKey) + GetExponentIntegerLength(key.PublicKey);

		foreach (RsaPrivateComponent component in PrivateComponents)
		{
			length += GetIntegerLength(key.GetLength(component), IsPadded(paddedComponents, component));
		}

		return length;
	}

	private static bool IsPadded(int paddedComponents, RsaPrivateComponent component)
	{
		return (paddedComponents >> (int)component & 1) is not 0;
	}

	// The modulus has its top bit set where its length in bits is a multiple of 8.
	private static int GetModulusIntegerLength(RsaPublicOperation key)
	{
		return GetIntegerLength(key.ModulusLength, key.ModulusBits % 8 is 0);
	}

	[SkipLocalsInit]
	private static int GetExponentIntegerLength(RsaPublicOperation key)
	{
		Span<byte> exponent = stackalloc byte[key.ExponentLength];
		key.WriteExponent(exponent);
		return GetIntegerLength(exponent.Length, exponent[0] >= 0x80);
	}

	private static int WriteModulus(RsaPublicOperation key, Span<byte> destination)
	{
		int offset = WriteIntegerHeader(key.ModulusLength, key.ModulusBits % 8 is 0, destination);
		key.WriteModulus(destination.Slice(offset, key.ModulusLength));
		return offset + key.ModulusLength;
	}

	[SkipLocalsInit]
	private static int WriteExponent(RsaPublicOperation key, Span<byte> destination)
	{
		Span<byte> exponent = stackalloc byte[key.ExponentLength];
		key.WriteExponent(exponent);
		int offset = WriteIntegerHeader(exponent.Length, exponent[0] >= 0x80, destination);
		exponent.CopyTo(destination.Slice(offset));
		return offset + exponent.Length;
	}

	// An INTEGER of a positive value of valueLength bytes without leading zeros, after a zero byte if padded, as its top bit is set.
	private static int GetIntegerLength(int valueLength, bool padded)
	{
		return KeyInfoDer.GetEncodedLength(valueLength + (padded ? 1 : 0));
	}

	// The header of such an INTEGER and its zero byte; the value follows.
	private static int WriteIntegerHeader(int valueLength, bool padded, Span<byte> destination)
	{
		int offset = WriteHeader(0x02, valueLength + (padded ? 1 : 0), destination);

		if (padded)
		{
			destination[offset++] = 0x00;
		}

		return offset;
	}

	// The one-byte tag and the DER length of contentLength bytes.
	private static int WriteHeader(byte tag, int contentLength, Span<byte> destination)
	{
		int headerLength = KeyInfoDer.GetEncodedLength(contentLength) - contentLength;
		destination[0] = tag;

		if (headerLength is 2)
		{
			destination[1] = (byte)contentLength;
			return 2;
		}

		destination[1] = (byte)(0x80 | headerLength - 2);

		for (int i = headerLength - 1; i >= 2; --i)
		{
			destination[i] = (byte)contentLength;
			contentLength >>= 8;
		}

		return headerLength;
	}

	// Reads DER values in order, as slices of the source. Malformed input throws AsnContentException.
	private ref struct DerSpanReader(ReadOnlySpan<byte> source)
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
}
