using CryptoBase.EllipticCurves;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Platform;
using System.Formats.Asn1;

namespace CryptoBase.Signatures.Ecdsa;

// algorithmIdentifier is the DER of id-ecPublicKey with the named curve. Nothing on the signing path branches on or indexes by a secret, except the retries of the nonce derivation. As with ECKey, keep a key in one writable location and do not copy it.
internal struct EcdsaKey<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	// The SEQUENCE header and the OID of id-ecPublicKey, which come before the named curve in an AlgorithmIdentifier.
	private const int CurveOffset = 11;

	private const int AdditionalDataLength = 32;

	private ECKey<TCurve, TField, TOrder> _key;
	private AffinePoint<TField>[]? _pointTable;
	private bool _verified;

	internal static int PrivateKeyLength => ECKey<TCurve, TField, TOrder>.PrivateKeyLength;

	internal static int PublicKeyLength => ECKey<TCurve, TField, TOrder>.PublicKeyLength;

	internal readonly bool HasPrivateKey => _key.HasPrivateKey;

	private static Asn1Tag ParametersTag => new(TagClass.ContextSpecific, 0, true);

	private static Asn1Tag PublicKeyTag => new(TagClass.ContextSpecific, 1, true);

	internal static int GetSubjectPublicKeyInfoLength(ReadOnlySpan<byte> algorithmIdentifier)
	{
		return KeyInfoDer.GetSubjectPublicKeyInfoLength(algorithmIdentifier, PublicKeyLength);
	}

	internal readonly int GetPkcs8PrivateKeyLength(ReadOnlySpan<byte> algorithmIdentifier)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		return KeyInfoDer.GetPrivateKeyInfoLength(algorithmIdentifier, GetECPrivateKeyLength(NamedCurve(algorithmIdentifier)));
	}

	internal void GenerateKey()
	{
		DropPointTable();
		_key.GenerateKey();
	}

	internal void ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		DropPointTable();

		if (!_key.TryImportPrivateKey(source))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportPublicKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PublicKeyLength, nameof(source));

		DropPointTable();

		if (!_key.TryImportPublicKey(source))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> source)
	{
		DropPointTable();

		if (!KeyInfoDer.TryReadSubjectPublicKeyInfo(algorithmIdentifier, source, out ReadOnlySpan<byte> publicKey) || !_key.TryImportPublicKey(publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportPkcs8PrivateKey(ReadOnlySpan<byte> algorithmIdentifier, ReadOnlySpan<byte> source)
	{
		DropPointTable();

		if (!KeyInfoDer.TryReadPrivateKeyInfo(algorithmIdentifier, source, out ReadOnlySpan<byte> privateKey, out ReadOnlySpan<byte> publicKey)
			|| !TryImportECPrivateKey(NamedCurve(algorithmIdentifier), privateKey)
			|| !publicKey.IsEmpty && !MatchesPublicKey(publicKey))
		{
			Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		return _key.ExportPrivateKey(destination);
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		return _key.ExportPublicKey(destination);
	}

	[SkipLocalsInit]
	internal readonly int ExportSubjectPublicKeyInfo(ReadOnlySpan<byte> algorithmIdentifier, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, GetSubjectPublicKeyInfoLength(algorithmIdentifier), nameof(destination));

		Span<byte> publicKey = stackalloc byte[PublicKeyLength];
		_key.ExportPublicKey(publicKey);
		return KeyInfoDer.WriteSubjectPublicKeyInfo(algorithmIdentifier, publicKey, destination);
	}

	[SkipLocalsInit]
	internal readonly int ExportPkcs8PrivateKey(ReadOnlySpan<byte> algorithmIdentifier, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, GetPkcs8PrivateKeyLength(algorithmIdentifier), nameof(destination));

		ReadOnlySpan<byte> curve = NamedCurve(algorithmIdentifier);
		int length = GetECPrivateKeyLength(curve);
		using CryptoBuffer<byte> privateKey = new(stackalloc byte[PrivateKeyLength]);
		using CryptoBuffer<byte> ecPrivateKey = new(stackalloc byte[length]);
		Span<byte> publicKey = stackalloc byte[PublicKeyLength];
		_key.ExportPrivateKey(privateKey.Span);
		_key.ExportPublicKey(publicKey);
		AsnWriter writer = new(AsnEncodingRules.DER, length);

		try
		{
			using (writer.PushSequence())
			{
				writer.WriteInteger(1);
				writer.WriteOctetString(privateKey.Span);

				using (writer.PushSequence(ParametersTag))
				{
					writer.WriteEncodedValue(curve);
				}

				using (writer.PushSequence(PublicKeyTag))
				{
					writer.WriteBitString(publicKey);
				}
			}

			writer.Encode(ecPrivateKey.Span);
		}
		finally
		{
			writer.Reset();
		}

		return KeyInfoDer.WritePrivateKeyInfo(algorithmIdentifier, ecPrivateKey.Span, destination);
	}

	internal static bool Supports(SignatureAlgorithm algorithm)
	{
		return algorithm is SignatureAlgorithm.EcdsaSha256 or SignatureAlgorithm.EcdsaSha384 or SignatureAlgorithm.EcdsaSha512;
	}

	internal static int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ThrowIfUnsupported(algorithm);
		return EcdsaEncoding<TOrder>.MaxDerLength;
	}

	[SkipLocalsInit]
	internal readonly int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ThrowIfCannotSign(algorithm, EcdsaSignatureFormat.Der, destination);

		using CryptoBuffer<byte> additionalData = new(stackalloc byte[AdditionalDataLength]);
		SystemRandom.Fill(additionalData.Span);
		return SignMessage(algorithm, message, additionalData.Span, EcdsaSignatureFormat.Der, destination);
	}

	internal readonly int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format, Span<byte> destination)
	{
		ThrowIfCannotSign(algorithm, format, destination);
		return SignMessage(algorithm, message, additionalData, format, destination);
	}

	internal readonly int SignHash(SignatureAlgorithm algorithm, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format, Span<byte> destination)
	{
		ThrowIfCannotSign(algorithm, format, destination);
		return SignHashCore(algorithm, hash, additionalData, format, destination);
	}

	internal bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		return Verify(algorithm, message, signature, EcdsaSignatureFormat.Der);
	}

	[SkipLocalsInit]
	internal bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
	{
		ThrowIfUnsupported(algorithm);

		Span<byte> hash = stackalloc byte[Sha512Core.HashSizeInBytes];
		int hashLength = Hash(algorithm, message, hash);
		return VerifyHash(hash.Slice(0, hashLength), signature, format);
	}

	internal bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
	{
		return EcdsaEncoding<TOrder>.TryRead(format, signature, out FieldElement<TOrder> r, out FieldElement<TOrder> s) && Verify(hash, in r, in s);
	}

	internal void Clear()
	{
		_key.Clear();
		DropPointTable();
	}

	private static void ThrowIfUnsupported(SignatureAlgorithm algorithm)
	{
		if (!Supports(algorithm))
		{
			ThrowHelper.ThrowUnsupportedSignatureAlgorithm(nameof(algorithm));
		}
	}

	private static ReadOnlySpan<byte> NamedCurve(ReadOnlySpan<byte> algorithmIdentifier)
	{
		ReadOnlySpan<byte> curve = algorithmIdentifier.Slice(CurveOffset);
		Debug.Assert(curve is [0x06, var length, ..] && curve.Length == 2 + length);
		return curve;
	}

	private static int GetECPrivateKeyLength(ReadOnlySpan<byte> curve)
	{
		int publicKeyLength = KeyInfoDer.GetEncodedLength(KeyInfoDer.GetEncodedLength(1 + PublicKeyLength));
		return KeyInfoDer.GetEncodedLength(3 + KeyInfoDer.GetEncodedLength(PrivateKeyLength) + KeyInfoDer.GetEncodedLength(curve.Length) + publicKeyLength);
	}

	// The algorithm is supported.
	private static int Hash(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		return algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 when PlatformSha256.IsPreferredFor(message.Length) => SHA256.HashData(message, destination),
			SignatureAlgorithm.EcdsaSha256 => HashAlgorithm<Sha256Core>.HashData(message, destination),
			SignatureAlgorithm.EcdsaSha384 => HashAlgorithm<Sha384Core>.HashData(message, destination),
			_ => HashAlgorithm<Sha512Core>.HashData(message, destination)
		};
	}

	private readonly void ThrowIfCannotSign(SignatureAlgorithm algorithm, EcdsaSignatureFormat format, Span<byte> destination)
	{
		ThrowIfUnsupported(algorithm);

		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EcdsaEncoding<TOrder>.GetMaxLength(format), nameof(destination));
	}

	private bool TryImportECPrivateKey(ReadOnlySpan<byte> curve, ReadOnlySpan<byte> source)
	{
		ReadOnlySpan<byte> publicKey = default;

		try
		{
			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
			ReadOnlySpan<byte> contents = source.Slice(offset, length);

			if (consumed != source.Length || !AsnDecoder.TryReadInt32(contents, AsnEncodingRules.DER, out int version, out consumed) || version is not 1)
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!AsnDecoder.TryReadPrimitiveOctetString(contents, AsnEncodingRules.DER, out ReadOnlySpan<byte> privateKey, out consumed) || privateKey.Length != PrivateKeyLength)
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!contents.IsEmpty && Asn1Tag.Decode(contents, out _) == ParametersTag)
			{
				AsnDecoder.ReadSequence(contents, AsnEncodingRules.DER, out offset, out length, out consumed, ParametersTag);

				if (!contents.Slice(offset, length).SequenceEqual(curve))
				{
					return false;
				}

				contents = contents.Slice(consumed);
			}

			if (!contents.IsEmpty)
			{
				AsnDecoder.ReadSequence(contents, AsnEncodingRules.DER, out offset, out length, out consumed, PublicKeyTag);
				ReadOnlySpan<byte> bitString = contents.Slice(offset, length);

				if (!AsnDecoder.TryReadPrimitiveBitString(bitString, AsnEncodingRules.DER, out int unusedBits, out publicKey, out int bitStringLength)
					|| unusedBits is not 0
					|| bitStringLength != bitString.Length
					|| publicKey.IsEmpty)
				{
					return false;
				}

				contents = contents.Slice(consumed);
			}

			if (!contents.IsEmpty || !_key.TryImportPrivateKey(privateKey))
			{
				return false;
			}
		}
		catch (AsnContentException)
		{
			return false;
		}

		return publicKey.IsEmpty || MatchesPublicKey(publicKey);
	}

	[SkipLocalsInit]
	private readonly bool MatchesPublicKey(ReadOnlySpan<byte> publicKey)
	{
		Span<byte> encoding = stackalloc byte[PublicKeyLength];
		_key.ExportPublicKey(encoding);
		return publicKey.SequenceEqual(encoding);
	}

	// The algorithm is supported.
	[SkipLocalsInit]
	private readonly int SignMessage(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format, Span<byte> destination)
	{
		Span<byte> hash = stackalloc byte[Sha512Core.HashSizeInBytes];
		int hashLength = Hash(algorithm, message, hash);
		return SignHashCore(algorithm, hash.Slice(0, hashLength), additionalData, format, destination);
	}

	// The algorithm is supported.
	private readonly int SignHashCore(SignatureAlgorithm algorithm, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format, Span<byte> destination)
	{
		return algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => SignHash<Sha256Core>(hash, additionalData, format, destination),
			SignatureAlgorithm.EcdsaSha384 => SignHash<Sha384Core>(hash, additionalData, format, destination),
			_ => SignHash<Sha512Core>(hash, additionalData, format, destination)
		};
	}

	[SkipLocalsInit]
	private readonly int SignHash<THash>(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format, Span<byte> destination)
		where THash : unmanaged, IHmacHashCore<THash>
	{
		int length = TOrder.ByteLength;
		ref readonly FieldElement<TOrder> privateKey = ref _key.PrivateScalar;
		using CryptoBuffer<byte> encodedPrivateKey = new(stackalloc byte[length]);
		Span<byte> encodedHash = stackalloc byte[length];
		Unsafe.SkipInit(out EcdsaNonce<THash, TOrder> nonce);
		Unsafe.SkipInit(out FieldElement<TOrder> k);
		Unsafe.SkipInit(out FieldElement<TOrder> inverse);
		Unsafe.SkipInit(out FieldElement<TOrder> sum);

		try
		{
			EcdsaEncoding<TOrder>.ImportHash(hash, out FieldElement<TOrder> e);
			FieldElement<TOrder>.Export(in e, encodedHash);
			FieldElement<TOrder>.Export(in privateKey, encodedPrivateKey.Span);
			nonce.Initialize(encodedPrivateKey.Span, encodedHash, additionalData);
			FieldElement<TOrder> r;
			FieldElement<TOrder> s;

			do
			{
				nonce.Next(out k);
				ECGroup<TCurve, TField, TOrder>.MultiplyBaseReduceX(in k, out r);
				// rR · d · R⁻¹ = r·d, and k⁻¹R · (e + r·d) · R⁻¹ = s, in plain form.
				FieldElement<TOrder>.ToMontgomery(in r, out s);
				FieldElement<TOrder>.Multiply(in s, in privateKey, out sum);
				FieldElement<TOrder>.Add(in e, in sum, out sum);
				FieldElement<TOrder>.ToMontgomery(in k, out inverse);
				FieldElement<TOrder>.Invert(in inverse, out inverse);
				FieldElement<TOrder>.Multiply(in inverse, in sum, out s);
			}
			while ((FieldElement<TOrder>.IsZero(in r) | FieldElement<TOrder>.IsZero(in s)) is not 0);

			return EcdsaEncoding<TOrder>.Write(format, in r, in s, destination);
		}
		finally
		{
			nonce.Clear();
			k.ZeroMemory();
			inverse.ZeroMemory();
			sum.ZeroMemory();
		}
	}

	// Every input is public, so s⁻¹ and R = u1·G + u2·Q may take variable time. The first verification goes without the table of Q, which a key that verifies once has no use for, and a later one builds it. Threads that verify at once may each build one, but only the first to finish publishes it, the others discard theirs, and the paths with and without it give the same R.
	private bool Verify(ReadOnlySpan<byte> hash, in FieldElement<TOrder> r, in FieldElement<TOrder> s)
	{
		EcdsaEncoding<TOrder>.ImportHash(hash, out FieldElement<TOrder> e);
		// s⁻¹R times a plain value is a plain product.
		FieldElement<TOrder>.ToMontgomery(in s, out FieldElement<TOrder> inverse);
		FieldElement<TOrder>.InvertVariableTime(in inverse, out inverse);
		FieldElement<TOrder>.Multiply(in inverse, in e, out FieldElement<TOrder> u1);
		FieldElement<TOrder>.Multiply(in inverse, in r, out FieldElement<TOrder> u2);
		AffinePoint<TField>[]? table = _pointTable;
		JacobianPoint<TField> point;

		if (table is null && !_verified)
		{
			_verified = true;
			ECVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(in u1, in _key.PublicPoint, in u2, out point);
		}
		else
		{
			ECVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(in u1, table ?? PublishPointTable(), in u2, out point);
		}

		return ECVariableTimeGroup<TCurve, TField, TOrder>.XModOrderEquals(in point, in r);
	}

	private AffinePoint<TField>[] PublishPointTable()
	{
		AffinePoint<TField>[] table = ECVariableTimePointTable<TCurve, TField, TOrder>.Build(in _key.PublicPoint);
		return Interlocked.CompareExchange(ref _pointTable, table, null) ?? table;
	}

	// The table follows from the public key, so whatever replaces or clears the key drops it.
	private void DropPointTable()
	{
		_pointTable = null;
		_verified = false;
	}
}
