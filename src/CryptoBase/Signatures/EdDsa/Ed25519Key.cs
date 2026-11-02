using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.Curve25519;
using CryptoBase.Hashes.Sha2;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Signatures.EdDsa;

// Ed25519, Ed25519ctx and Ed25519ph of RFC 8032 §5.1, with the key expanded once: the private key, a 32-byte seed, gives s, kept in Montgomery form, and the prefix; the public key A is kept as its encoding and as −A, from which verification computes [S]B − [k]A. Nothing on the signing path branches on or indexes by the seed, s, the prefix or r. Keep a key in one writable location and do not copy it: a copy keeps the private key where Clear cannot reach it.
internal struct Ed25519Key
{
	internal const int PrivateKeyLength = 32;
	internal const int PublicKeyLength = Edwards25519.EncodedLength;
	internal const int SignatureLength = PublicKeyLength + Ed25519Scalar.Length;
	internal const int MaxContextLength = byte.MaxValue;

	// The length of SHA-512, and of the hash that Ed25519ph signs.
	internal const int HashLength = Sha512Core.HashSizeInBytes;

	// The phflag of dom2 (RFC 8032 §2).
	private const byte ContextFlag = 0;
	private const byte PreHashFlag = 1;

	// CurvePrivateKey (RFC 8410 §7): an OCTET STRING of the seed.
	private const int CurvePrivateKeyLength = 2 + PrivateKeyLength;

	private InlineArray32<byte> _privateKey;
	private InlineArray32<byte> _prefix;
	private FieldElement<Ed25519Order> _montgomeryScalar;
	private InlineArray32<byte> _publicKey;
	private EdwardsPoint _negatedPoint;
	private EdwardsNielsPoint[]? _pointTable;
	private bool _verified;

	// id-Ed25519 (RFC 8410 §3), whose parameters are absent.
	internal static ReadOnlySpan<byte> AlgorithmIdentifier => [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];

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

	// The prefix of dom2 (RFC 8032 §2).
	private static ReadOnlySpan<byte> DomainPrefix => "SigEd25519 no Ed25519 collisions"u8;

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
		return algorithm is SignatureAlgorithm.Ed25519;
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

	// Ed25519 for an empty context, whose dom2 is empty, and Ed25519ctx otherwise.
	internal readonly int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> destination)
	{
		ThrowIfCannotSign(context, destination);

		ReadOnlySpan<byte> header = context.IsEmpty ? [] : [ContextFlag, (byte)context.Length];
		SignCore(header, context, message, destination);
		return SignatureLength;
	}

	internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThan(context.Length, MaxContextLength, nameof(context));

		ReadOnlySpan<byte> header = context.IsEmpty ? [] : [ContextFlag, (byte)context.Length];
		return VerifyCore(header, context, message, signature);
	}

	// Ed25519ph, whose PH is SHA-512, of the hash that the caller computed.
	internal readonly int SignPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> context, Span<byte> destination)
	{
		ThrowIfCannotSign(context, destination);
		ArgumentOutOfRangeException.ThrowIfNotEqual(hash.Length, HashLength, nameof(hash));

		SignCore([PreHashFlag, (byte)context.Length], context, hash, destination);
		return SignatureLength;
	}

	internal bool VerifyPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(hash.Length, HashLength, nameof(hash));
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

	// SHA-512(dom2(F, C) ‖ first ‖ second ‖ message), where header is F ‖ OLEN(C), or empty for Ed25519, whose dom2 is empty. The state, which may hold the prefix or the seed, is erased.
	private static void Hash(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		Hash<Sha512Core>(header, context, first, second, message, destination);
	}

	// Generic so that the explicit members of the core are called without boxing.
	private static void Hash<THash>(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> message, Span<byte> destination)
		where THash : unmanaged, IHashCore<THash>
	{
		THash state = THash.Create();

		if (!header.IsEmpty)
		{
			state.Append(DomainPrefix);
			state.Append(header);
			state.Append(context);
		}

		state.Append(first);
		state.Append(second);
		state.Append(message);
		state.Finalize(destination);
		state.ZeroMemory();
	}

	// RFC 8032 §5.1.5: s is the first half of SHA-512(seed), pruned, A = [s]B, and the prefix is the second half. One inversion gives the affine A for both its encoding and −A, so that the coordinates of the product, which depend on s, need not be kept.
	[SkipLocalsInit]
	private void SetPrivateKey(ReadOnlySpan<byte> seed)
	{
		DropPointTable();

		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);
		Hash([], [], seed, [], [], hash.Span);
		Span<byte> scalar = hash.Span.Slice(0, Ed25519Scalar.Length);
		scalar[0] &= 0xF8;
		scalar[Ed25519Scalar.Length - 1] = (byte)(scalar[Ed25519Scalar.Length - 1] & 0x7F | 0x40);
		Edwards25519.MultiplyBase(scalar, out EdwardsPoint point);
		Field25519.Invert(in point.Z, out Field25519 inverse);
		Field25519.Multiply(in point.X, in inverse, out Field25519 x);
		Field25519.Multiply(in point.Y, in inverse, out Field25519 y);
		Field25519.ToBytes(in y, _publicKey);
		_publicKey[PublicKeyLength - 1] |= (byte)(Field25519.IsNegative(in x) & 0x80);
		Field25519.Negate(in x, out _negatedPoint.X);
		_negatedPoint.Y = y;
		_negatedPoint.Z = Field25519.One;
		Field25519.Multiply(in _negatedPoint.X, in y, out _negatedPoint.T);
		Ed25519Scalar.ToMontgomery(scalar, out _montgomeryScalar);
		hash.Span.Slice(Ed25519Scalar.Length).CopyTo(_prefix);
		seed.CopyTo(_privateKey);
		HasPrivateKey = true;
		point.ZeroMemory();
		inverse.ZeroMemory();
	}

	// RFC 8032 §5.1.3, strictly; false, with the key cleared, for a public key that does not decode.
	private bool TrySetPublicKey(ReadOnlySpan<byte> source)
	{
		Clear();

		if (source.Length is not PublicKeyLength || !Edwards25519.TryDecode(source, out EdwardsPoint point))
		{
			return false;
		}

		source.CopyTo(_publicKey);
		Edwards25519.Negate(in point, out _negatedPoint);
		return true;
	}

	// RFC 8032 §5.1.6. r is secret until R hides it, and the signature is written after the last read of the message, which may overlap destination.
	[SkipLocalsInit]
	private readonly void SignCore(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[HashLength + Ed25519Scalar.Length]);
		Span<byte> hash = buffer.Span.Slice(0, HashLength);
		Span<byte> nonce = buffer.Span.Slice(HashLength);
		Span<byte> encodedR = stackalloc byte[PublicKeyLength];
		Unsafe.SkipInit(out FieldElement<Ed25519Order> r);
		Unsafe.SkipInit(out EdwardsPoint point);

		try
		{
			Hash(header, context, _prefix, [], message, hash);
			Ed25519Scalar.ReduceWide(hash, out r);
			Ed25519Scalar.Write(in r, nonce);
			Edwards25519.MultiplyBase(nonce, out point);
			Edwards25519.Encode(in point, encodedR);
			Hash(header, context, encodedR, PublicKey, message, hash);
			Ed25519Scalar.ReduceWide(hash, out FieldElement<Ed25519Order> k);
			Ed25519Scalar.MultiplyAdd(in k, in _montgomeryScalar, in r, out FieldElement<Ed25519Order> s);
			encodedR.CopyTo(destination);
			Ed25519Scalar.Write(in s, destination.Slice(PublicKeyLength, Ed25519Scalar.Length));
		}
		finally
		{
			r.ZeroMemory();
			point.ZeroMemory();
		}
	}

	// RFC 8032 §5.1.7 with the cofactorless equation and k mod L: S must be below L, and R must equal the canonical encoding of R' = [S]B − [k]A. Every input is public, so the product takes variable time. The first verification goes without the table of −A, which a key that verifies once has no use for, and a later one builds it. Threads that verify at once may each build one, but only the first to finish publishes it, and the paths with and without it give the same R'.
	[SkipLocalsInit]
	private bool VerifyCore(ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		if (signature.Length is not SignatureLength)
		{
			return false;
		}

		ReadOnlySpan<byte> encodedR = signature.Slice(0, PublicKeyLength);
		ReadOnlySpan<byte> s = signature.Slice(PublicKeyLength);

		if (!Ed25519Scalar.IsCanonical(s))
		{
			return false;
		}

		Span<byte> hash = stackalloc byte[HashLength];
		Hash(header, context, encodedR, PublicKey, message, hash);
		Ed25519Scalar.ReduceWide(hash, out FieldElement<Ed25519Order> k);
		Span<byte> encodedK = hash.Slice(0, Ed25519Scalar.Length);
		Ed25519Scalar.Write(in k, encodedK);
		EdwardsNielsPoint[]? table = _pointTable;
		EdwardsPoint point;

		if (table is null && !_verified)
		{
			_verified = true;
			Edwards25519.DoubleScalarMultiplyVariableTime(encodedK, in _negatedPoint, s, out point);
		}
		else
		{
			Edwards25519.DoubleScalarMultiplyVariableTime(encodedK, table ?? PublishPointTable(), s, out point);
		}

		Span<byte> encoded = hash.Slice(Ed25519Scalar.Length);
		Edwards25519.EncodeVariableTime(in point, encoded);
		return encoded.SequenceEqual(encodedR);
	}

	private EdwardsNielsPoint[] PublishPointTable()
	{
		EdwardsNielsPoint[] table = EdwardsVariableTimePointTable.Build(in _negatedPoint);
		return Interlocked.CompareExchange(ref _pointTable, table, null) ?? table;
	}

	// The table follows from the public key, so whatever replaces or clears the key drops it.
	private void DropPointTable()
	{
		_pointTable = null;
		_verified = false;
	}
}
