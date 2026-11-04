using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.Curve448;
using CryptoBase.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Signatures.EdDsa;

// Ed448 and Ed448ph of RFC 8032 §5.2, with the key expanded once: the private key, a 57-byte seed, gives s, kept in Montgomery form, and the prefix; the public key A is kept as its encoding and as −A, from which verification computes [S]B − [k]A. Nothing on the signing path branches on or indexes by the seed, s, the prefix or r. Keep a key in one writable location and do not copy it: a copy keeps the private key where Clear cannot reach it.
internal struct Ed448Key
{
	internal const int PrivateKeyLength = 57;
	internal const int PublicKeyLength = Edwards448.EncodedLength;
	internal const int SignatureLength = PublicKeyLength + Ed448Scalar.Length;
	internal const int MaxContextLength = byte.MaxValue;

	// The length of PH(M) = SHAKE256(M, 64).
	internal const int PreHashLength = 64;

	// The output length of SHAKE256 in RFC 8032 §5.2.
	private const int HashLength = Ed448Scalar.WideLength;

	// The phflag of dom4 (RFC 8032 §2).
	private const byte ContextFlag = 0;
	private const byte PreHashFlag = 1;

	// CurvePrivateKey (RFC 8410 §7): an OCTET STRING of the seed.
	private const int CurvePrivateKeyLength = 2 + PrivateKeyLength;

	private InlineArray57<byte> _privateKey;
	private InlineArray57<byte> _prefix;
	private FieldElement<Ed448Order> _montgomeryScalar;
	private InlineArray57<byte> _publicKey;
	private EdwardsPoint _negatedPoint;
	private EdwardsAffinePoint[]? _pointTable;
	private bool _verified;

	// id-Ed448 (RFC 8410 §3), whose parameters are absent.
	internal static ReadOnlySpan<byte> AlgorithmIdentifier => [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71];

	internal static int SubjectPublicKeyInfoLength => KeyInfoDer.GetSubjectPublicKeyInfoLength(AlgorithmIdentifier, PublicKeyLength);

	internal readonly int Pkcs8PrivateKeyLength
	{
		get
		{
			if (!HasPrivateKey)
			{
				ThrowHelper.ThrowMissingKey("private key");
			}

			return KeyInfoDer.GetPrivateKeyInfoLength(AlgorithmIdentifier, CurvePrivateKeyLength);
		}
	}

	internal bool HasPrivateKey { readonly get; private set; }

	// The prefix of dom4 (RFC 8032 §2).
	private static ReadOnlySpan<byte> DomainPrefix => "SigEd448"u8;

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> PublicKey => _publicKey;

	// If drawing the seed throws, the key stays as it was.
	[SkipLocalsInit]
	internal void GenerateKey()
	{
		using CryptoBuffer<byte> seed = new(stackalloc byte[PrivateKeyLength]);
		SystemRandom.Fill(seed.Span);
		SetPrivateKey(seed.Span);
	}

	internal void ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		SetPrivateKey(source);
	}

	internal void ImportPublicKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PublicKeyLength, nameof(source));

		if (!TrySetPublicKey(source))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		if (!KeyInfoDer.TryReadSubjectPublicKeyInfo(AlgorithmIdentifier, source, out ReadOnlySpan<byte> publicKey) || !TrySetPublicKey(publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	// privateKey holds a CurvePrivateKey in DER, and a publicKey of OneAsymmetricKey must match the private key.
	internal void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		if (KeyInfoDer.TryReadPrivateKeyInfo(AlgorithmIdentifier, source, out ReadOnlySpan<byte> privateKey, out ReadOnlySpan<byte> publicKey)
			&& privateKey is [0x04, PrivateKeyLength, .. var seed] && seed.Length is PrivateKeyLength)
		{
			SetPrivateKey(seed);

			if (publicKey.IsEmpty || publicKey.SequenceEqual(PublicKey))
			{
				return;
			}
		}

		Clear();
		ThrowHelper.ThrowInvalidKey(nameof(source));
	}

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateKeyLength, nameof(destination));

		((ReadOnlySpan<byte>)_privateKey).CopyTo(destination);
		return PrivateKeyLength;
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PublicKeyLength, nameof(destination));

		PublicKey.CopyTo(destination);
		return PublicKeyLength;
	}

	internal readonly int ExportSubjectPublicKeyInfo(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SubjectPublicKeyInfoLength, nameof(destination));

		return KeyInfoDer.WriteSubjectPublicKeyInfo(AlgorithmIdentifier, PublicKey, destination);
	}

	// Version 1, without the public key, which RFC 8410 §7 leaves optional.
	[SkipLocalsInit]
	internal readonly int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, Pkcs8PrivateKeyLength, nameof(destination));

		using CryptoBuffer<byte> curvePrivateKey = new(stackalloc byte[CurvePrivateKeyLength]);
		curvePrivateKey.Span[0] = 0x04;
		curvePrivateKey.Span[1] = PrivateKeyLength;
		((ReadOnlySpan<byte>)_privateKey).CopyTo(curvePrivateKey.Span.Slice(2));
		return KeyInfoDer.WritePrivateKeyInfo(AlgorithmIdentifier, curvePrivateKey.Span, destination);
	}

	internal static bool Supports(SignatureAlgorithm algorithm)
	{
		return algorithm is SignatureAlgorithm.Ed448;
	}

	internal static int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ThrowIfUnsupported(algorithm);
		return SignatureLength;
	}

	internal readonly int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ThrowIfUnsupported(algorithm);
		return Sign(message, default, destination);
	}

	internal bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ThrowIfUnsupported(algorithm);
		return Verify(message, signature, default);
	}

	// Ed448, whose dom4 is there even for an empty context.
	internal readonly int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> destination)
	{
		ThrowIfCannotSign(context, destination);

		SignCore([ContextFlag, (byte)context.Length], context, message, destination);
		return SignatureLength;
	}

	internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThan(context.Length, MaxContextLength, nameof(context));

		return VerifyCore([ContextFlag, (byte)context.Length], context, message, signature);
	}

	// Ed448ph, whose PH is SHAKE256 with 64 bytes of output, of the hash that the caller computed.
	internal readonly int SignPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> context, Span<byte> destination)
	{
		ThrowIfCannotSign(context, destination);
		ArgumentOutOfRangeException.ThrowIfNotEqual(hash.Length, PreHashLength, nameof(hash));

		SignCore([PreHashFlag, (byte)context.Length], context, hash, destination);
		return SignatureLength;
	}

	internal bool VerifyPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(hash.Length, PreHashLength, nameof(hash));
		ArgumentOutOfRangeException.ThrowIfGreaterThan(context.Length, MaxContextLength, nameof(context));

		return VerifyCore([PreHashFlag, (byte)context.Length], context, hash, signature);
	}

	internal void Clear()
	{
		_privateKey.ZeroMemory();
		_prefix.ZeroMemory();
		_montgomeryScalar.ZeroMemory();
		_publicKey.ZeroMemory();
		_negatedPoint.ZeroMemory();
		HasPrivateKey = false;
		DropPointTable();
	}

	private static void ThrowIfUnsupported(SignatureAlgorithm algorithm)
	{
		if (!Supports(algorithm))
		{
			ThrowHelper.ThrowUnsupportedSignatureAlgorithm(nameof(algorithm));
		}
	}

	private readonly void ThrowIfCannotSign(ReadOnlySpan<byte> context, Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfGreaterThan(context.Length, MaxContextLength, nameof(context));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SignatureLength, nameof(destination));
	}

	// SHAKE256(dom4(F, C) ‖ first ‖ second ‖ message, 114), where header is F ‖ OLEN(C), or without dom4 for an empty header, as in the expansion of the seed. The state, which may hold the prefix or the seed, is erased.
	private static void Hash(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		Hash<Shake256Core>(header, context, first, second, message, destination);
	}

	// Generic so that the explicit members of the core are called without boxing.
	private static void Hash<TXof>(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> message, Span<byte> destination)
		where TXof : unmanaged, IXofCore<TXof>
	{
		TXof state = TXof.Create();

		if (!header.IsEmpty)
		{
			state.Append(DomainPrefix);
			state.Append(header);
			state.Append(context);
		}

		state.Append(first);
		state.Append(second);
		state.Append(message);
		state.Read(destination);
		state.ZeroMemory();
	}

	// RFC 8032 §5.2.5: s is the first 57 bytes of SHAKE256(seed, 114), pruned, A = [s]B, and the prefix is the other 57. Pruning clears the last byte of s, so only its first 56 are used. One inversion gives the affine A for both its encoding and −A, so that the coordinates of the product, which depend on s, need not be kept.
	[SkipLocalsInit]
	private void SetPrivateKey(ReadOnlySpan<byte> seed)
	{
		DropPointTable();

		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);
		Hash([], [], seed, [], [], hash.Span);
		Span<byte> scalar = hash.Span.Slice(0, Edwards448.ScalarLength);
		scalar[0] &= 0xFC;
		scalar[Edwards448.ScalarLength - 1] |= 0x80;
		Edwards448.MultiplyBase(scalar, out EdwardsPoint point);
		Field448.Invert(in point.Z, out Field448 inverse);
		Field448.Multiply(in point.X, in inverse, out Field448 x);
		Field448.Multiply(in point.Y, in inverse, out Field448 y);
		Span<byte> publicKey = _publicKey;
		Field448.ToBytes(in y, publicKey.Slice(0, Field448.ByteLength));
		publicKey[Field448.ByteLength] = (byte)(Field448.IsNegative(in x) & 0x80);
		Field448.Negate(in x, out _negatedPoint.X);
		_negatedPoint.Y = y;
		_negatedPoint.Z = Field448.One;
		Field448.Multiply(in _negatedPoint.X, in y, out _negatedPoint.T);
		Ed448Scalar.ToMontgomery(scalar, out _montgomeryScalar);
		hash.Span.Slice(PrivateKeyLength).CopyTo(_prefix);
		seed.CopyTo(_privateKey);
		HasPrivateKey = true;
		point.ZeroMemory();
		inverse.ZeroMemory();
	}

	// RFC 8032 §5.2.3, strictly; false, with the key cleared, for a public key that does not decode.
	private bool TrySetPublicKey(ReadOnlySpan<byte> source)
	{
		Clear();

		if (source.Length is not PublicKeyLength || !Edwards448.TryDecode(source, out EdwardsPoint point))
		{
			return false;
		}

		source.CopyTo(_publicKey);
		Edwards448.Negate(in point, out _negatedPoint);
		return true;
	}

	// RFC 8032 §5.2.6. r is secret until R hides it, and the signature is written after the last read of the message, which may overlap destination.
	[SkipLocalsInit]
	private readonly void SignCore(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[HashLength + Edwards448.ScalarLength]);
		Span<byte> hash = buffer.Span.Slice(0, HashLength);
		Span<byte> nonce = buffer.Span.Slice(HashLength);
		Span<byte> encodedR = stackalloc byte[PublicKeyLength];
		Unsafe.SkipInit(out FieldElement<Ed448Order> r);
		Unsafe.SkipInit(out EdwardsPoint point);

		try
		{
			Hash(header, context, _prefix, [], message, hash);
			Ed448Scalar.ReduceWide(hash, out r);
			Ed448Scalar.Write(in r, nonce);
			Edwards448.MultiplyBase(nonce, out point);
			Edwards448.Encode(in point, encodedR);
			Hash(header, context, encodedR, PublicKey, message, hash);
			Ed448Scalar.ReduceWide(hash, out FieldElement<Ed448Order> k);
			Ed448Scalar.MultiplyAdd(in k, in _montgomeryScalar, in r, out FieldElement<Ed448Order> s);
			encodedR.CopyTo(destination);
			Ed448Scalar.Write(in s, destination.Slice(PublicKeyLength, Ed448Scalar.Length));
		}
		finally
		{
			r.ZeroMemory();
			point.ZeroMemory();
		}
	}

	// RFC 8032 §5.2.7 with the cofactorless equation and k mod L: S must be below L, and R must equal the canonical encoding of R' = [S]B − [k]A. Every input is public, so the product takes variable time. The first verification goes without the table of −A, which a key that verifies once has no use for, and a later one builds it. Threads that verify at once may each build one, but only the first to finish publishes it, and the paths with and without it give the same R'.
	[SkipLocalsInit]
	private bool VerifyCore(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		if (signature.Length is not SignatureLength)
		{
			return false;
		}

		ReadOnlySpan<byte> encodedR = signature.Slice(0, PublicKeyLength);
		ReadOnlySpan<byte> s = signature.Slice(PublicKeyLength);

		if (!Ed448Scalar.IsCanonical(s))
		{
			return false;
		}

		// IsCanonical has checked that the last byte of S is 0.
		s = s.Slice(0, Edwards448.ScalarLength);
		Span<byte> hash = stackalloc byte[HashLength];
		Hash(header, context, encodedR, PublicKey, message, hash);
		Ed448Scalar.ReduceWide(hash, out FieldElement<Ed448Order> k);
		Span<byte> encodedK = hash.Slice(0, Edwards448.ScalarLength);
		Ed448Scalar.Write(in k, encodedK);
		EdwardsAffinePoint[]? table = _pointTable;
		EdwardsPoint point;

		if (table is null && !_verified)
		{
			_verified = true;
			Edwards448.DoubleScalarMultiplyVariableTime(encodedK, in _negatedPoint, s, out point);
		}
		else
		{
			Edwards448.DoubleScalarMultiplyVariableTime(encodedK, table ?? PublishPointTable(), s, out point);
		}

		Span<byte> encoded = hash.Slice(Edwards448.ScalarLength, PublicKeyLength);
		Edwards448.EncodeVariableTime(in point, encoded);
		return encoded.SequenceEqual(encodedR);
	}

	private EdwardsAffinePoint[] PublishPointTable()
	{
		EdwardsAffinePoint[] table = EdwardsVariableTimePointTable.Build(in _negatedPoint);
		return Interlocked.CompareExchange(ref _pointTable, table, null) ?? table;
	}

	// The table follows from the public key, so whatever replaces or clears the key drops it.
	private void DropPointTable()
	{
		_pointTable = null;
		_verified = false;
	}
}
