using System.Formats.Asn1;

namespace CryptoBase.Signatures.Rsa;

// The DER encodings of RSA keys: RSAPublicKey and RSAPrivateKey (RFC 8017, Appendices A.1.1 and A.1.2), and the AlgorithmIdentifiers that SubjectPublicKeyInfo and PKCS #8 carry them with (RFC 4055).
// Readers return slices of their source and throw ArgumentException for the parameter source, or NotSupportedException for a valid key or identifier that is not supported.
internal static class RsaKeyDer
{
	private const string RsassaPssOid = "1.2.840.113549.1.1.10";
	private const string SourceName = "source";

	// The length of INTEGER 0, the version of RSAPrivateKey.
	private const int VersionLength = 3;

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
			allowed = RsassaPssParameters.TryRead(parameters, out algorithm, out int hashLength, out int saltLength) && saltLength <= hashLength;
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
		int offset = KeyInfoDer.WriteHeader(0x30, GetModulusIntegerLength(key) + GetExponentIntegerLength(key), destination);
		offset += WriteModulus(key, destination.Slice(offset));
		offset += WriteExponent(key, destination.Slice(offset));
		return offset;
	}

	internal static int GetRsaPrivateKeyLength(RsaPrivateOperation key)
	{
		return KeyInfoDer.GetEncodedLength(GetRsaPrivateKeyContentLength(key));
	}

	// destination is at least GetRsaPrivateKeyLength long, and receives the private values directly.
	internal static int WriteRsaPrivateKey(RsaPrivateOperation key, Span<byte> destination)
	{
		RsaPublicOperation publicKey = key.PublicKey;
		int offset = KeyInfoDer.WriteHeader(0x30, GetRsaPrivateKeyContentLength(key), destination);
		destination[offset++] = 0x02;
		destination[offset++] = 0x01;
		destination[offset++] = 0x00;
		offset += WriteModulus(publicKey, destination.Slice(offset));
		offset += WriteExponent(publicKey, destination.Slice(offset));

		foreach (RsaPrivateComponent component in PrivateComponents)
		{
			int length = key.GetLength(component);
			offset += WriteIntegerHeader(length, key.IsTopBitSet(component), destination.Slice(offset));
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

	private static int GetRsaPrivateKeyContentLength(RsaPrivateOperation key)
	{
		int length = VersionLength + GetModulusIntegerLength(key.PublicKey) + GetExponentIntegerLength(key.PublicKey);

		foreach (RsaPrivateComponent component in PrivateComponents)
		{
			length += GetIntegerLength(key.GetLength(component), key.IsTopBitSet(component));
		}

		return length;
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
		int offset = KeyInfoDer.WriteHeader(0x02, valueLength + (padded ? 1 : 0), destination);

		if (padded)
		{
			destination[offset++] = 0x00;
		}

		return offset;
	}
}
