using CryptoBase.EllipticCurves;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.Kdf;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.SM2;

// The key of SM2Key: d in [1, n − 2] with its public key P = d·G, and (1 + d)⁻¹ once a signature has computed it, or P alone. EcdsaKey holds d and P, in the encodings that SM2 shares with ECDSA, id-ecPublicKey and a named curve, and its table of P for verification; the state holds the windows of P for encryption and key exchange and those of SM2VerificationCurve for verification. Nothing on the signing and decryption paths branches on or indexes by a secret, except the retries that GB/T 32918 prescribes. As with ECKey, keep a state in one writable location and do not copy it.
internal struct SM2KeyState
{
	internal const int HashLength = 32;

	// ENTL holds the bit length of an ID in 16 bits.
	internal const int MaxIdLength = ushort.MaxValue / 8;

	// C1 and C3 of a ciphertext C1 ‖ C3 ‖ C2.
	internal const int CiphertextOverhead = 65 + HashLength;

	private const int AdditionalDataLength = 32;

	// The encryption that builds the windows of P, once the encryptions before it have cost about what the build does, so that a key that encrypts only a few times does not pay for the build.
	private const int EncryptionTableThreshold = 6;

	// The verification that builds the windows of P of SM2VerificationCurve, by the same reckoning against the table of EcdsaKey, which the verifications from the second on take until then.
	private const int VerificationTableThreshold = 31;

	// The key exchange with P as the static key of the peer that builds the windows of P, by the same reckoning.
	private const int KeyExchangeTableThreshold = 20;

	private const int InverseMissing = 0;
	private const int InverseComputing = 1;
	private const int InverseReady = 2;

	private EcdsaKey<SM2Curve, SM2CurveField, SM2Order> _key;
	// (1 + d)⁻¹·R, (1 + d)⁻¹ in Montgomery form, once _inverseStage is InverseReady.
	private FieldElement<SM2Order> _inverse;
	private int _inverseStage;
	// Z of DefaultId, once a signature or verification with it has computed Z.
	private byte[]? _defaultZ;
	// The windows of P that the products of secret scalars scan, for encryption and key exchange, and those of SM2VerificationCurve, which verification reads at its digits.
	private ECPointTable<SM2Curve, SM2CurveField, SM2Order>? _table;
	private ECPointTable<SM2VerificationCurve, SM2CurveField, SM2Order>? _verificationTable;
	// The encryptions, the verifications and the key exchanges with P as the key of the peer so far, until the windows.
	private int _encryptions;
	private int _verifications;
	private int _exchanges;

	internal static int PrivateKeyLength => EcdsaKey<SM2Curve, SM2CurveField, SM2Order>.PrivateKeyLength;

	internal static int PublicKeyLength => EcdsaKey<SM2Curve, SM2CurveField, SM2Order>.PublicKeyLength;

	internal static int MaxSignatureLength => EcdsaEncoding<SM2Order>.MaxDerLength;

	// The DER of id-ecPublicKey with the named curve 1.2.156.10197.1.301 of SM2.
	internal static ReadOnlySpan<byte> AlgorithmIdentifier =>
	[
		0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D,
	];

	// The default ID of GB/T 35276-2017 (GM/T 0009-2012).
	internal static ReadOnlySpan<byte> DefaultId => "1234567812345678"u8;

	// a ‖ b ‖ xG ‖ yG, which every Z takes.
	private static readonly byte[] CurveParameters = EncodeCurveParameters();

	internal readonly bool HasPrivateKey => _key.HasPrivateKey;

	[UnscopedRef]
	internal readonly ref readonly ECKey<SM2Curve, SM2CurveField, SM2Order> Key => ref _key.Key;

	internal readonly int SubjectPublicKeyInfoLength => EcdsaKey<SM2Curve, SM2CurveField, SM2Order>.GetSubjectPublicKeyInfoLength(AlgorithmIdentifier);

	internal readonly int Pkcs8PrivateKeyLength => _key.GetPkcs8PrivateKeyLength(AlgorithmIdentifier);

	// Candidates in [1, n − 1] until one is not n − 1, so that d is uniform in [1, n − 2]; only that retry branches. If fill throws, the key stays as it was.
	[SkipLocalsInit]
	internal void GenerateKey(Action<Span<byte>> fill)
	{
		Unsafe.SkipInit(out FieldElement<SM2Order> privateKey);
		using CryptoBuffer<byte> encoded = new(stackalloc byte[PrivateKeyLength]);

		try
		{
			do
			{
				ECKey<SM2Curve, SM2CurveField, SM2Order>.GeneratePrivateScalar(fill, out privateKey);
			}
			while (IsLast(in privateKey) is not 0);

			FieldElement<SM2Order>.Export(in privateKey, encoded.Span);
			ImportPrivateKey(encoded.Span);
		}
		finally
		{
			privateKey.ZeroMemory();
		}
	}

	internal void ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		DropDerived();
		_key.ImportPrivateKey(source);
		RejectLast();
	}

	internal void ImportPublicKey(ReadOnlySpan<byte> source)
	{
		DropDerived();
		_key.ImportPublicKey(source);
	}

	internal void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		DropDerived();
		_key.ImportSubjectPublicKeyInfo(AlgorithmIdentifier, source);
	}

	internal void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		DropDerived();
		_key.ImportPkcs8PrivateKey(AlgorithmIdentifier, source);
		RejectLast();
	}

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		return _key.ExportPrivateKey(destination);
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		return _key.ExportPublicKey(destination);
	}

	internal readonly int ExportSubjectPublicKeyInfo(Span<byte> destination)
	{
		return _key.ExportSubjectPublicKeyInfo(AlgorithmIdentifier, destination);
	}

	internal readonly int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		return _key.ExportPkcs8PrivateKey(AlgorithmIdentifier, destination);
	}

	internal static bool Supports(SignatureAlgorithm algorithm)
	{
		return algorithm is SignatureAlgorithm.SM2SM3;
	}

	internal static void ThrowIfUnsupported(SignatureAlgorithm algorithm)
	{
		if (!Supports(algorithm))
		{
			ThrowHelper.ThrowUnsupportedSignatureAlgorithm(nameof(algorithm));
		}
	}

	internal static void ThrowIfInvalidId(ReadOnlySpan<byte> id, string parameterName)
	{
		if (id.Length > MaxIdLength)
		{
			throw new ArgumentException($"An ID holds at most {MaxIdLength} bytes.", parameterName);
		}
	}

	// Z = SM3(ENTL ‖ ID ‖ a ‖ b ‖ xG ‖ yG ‖ xA ‖ yA) of GB/T 32918.2-2016, Sec. 5.5, for the public key P = (xA, yA) of the state, with ENTL the bit length of ID in two big-endian bytes. Z of DefaultId is computed once and kept.
	[SkipLocalsInit]
	internal void ComputeZ(ReadOnlySpan<byte> id, Span<byte> destination)
	{
		Debug.Assert(id.Length <= MaxIdLength && destination.Length >= HashLength);

		bool isDefault = id.SequenceEqual(DefaultId);

		if (isDefault && _defaultZ is { } cached)
		{
			cached.CopyTo(destination);
			return;
		}

		Span<byte> publicKey = stackalloc byte[PublicKeyLength];
		_key.ExportPublicKey(publicKey);
		ComputeZ(id, publicKey, destination);

		if (isDefault)
		{
			Interlocked.CompareExchange(ref _defaultZ, destination.Slice(0, HashLength).ToArray(), null);
		}
	}

	// As above for the uncompressed encoding of P.
	[SkipLocalsInit]
	private static void ComputeZ(ReadOnlySpan<byte> id, ReadOnlySpan<byte> publicKey, Span<byte> destination)
	{
		Debug.Assert(id.Length <= MaxIdLength && publicKey.Length == PublicKeyLength);

		Span<byte> length = stackalloc byte[sizeof(ushort)];
		BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)(8 * id.Length));
		SM3Core hash = HashCore.Create<SM3Core>();
		HashCore.Append(ref hash, length);
		HashCore.Append(ref hash, id);
		HashCore.Append(ref hash, CurveParameters);
		HashCore.Append(ref hash, publicKey.Slice(1));
		HashCore.Finalize(ref hash, destination);
	}

	// As below, with fresh system randomness as the additional data.
	[SkipLocalsInit]
	internal int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> id, Span<byte> destination)
	{
		using CryptoBuffer<byte> additionalData = new(stackalloc byte[AdditionalDataLength]);
		SystemRandom.Fill(additionalData.Span);
		return Sign(message, id, additionalData.Span, destination);
	}

	// GB/T 32918.2-2016, Sec. 6.1: e = SM3(Z ‖ M) and the nonces of SM3Nonce over d, e mod n and additionalData, which empty makes deterministic.
	[SkipLocalsInit]
	internal int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> id, ReadOnlySpan<byte> additionalData, Span<byte> destination)
	{
		Debug.Assert(HasPrivateKey && destination.Length >= MaxSignatureLength);

		int length = SM2Order.ByteLength;
		ref readonly FieldElement<SM2Order> privateKey = ref _key.Key.PrivateScalar;
		Span<byte> hash = stackalloc byte[HashLength];
		using CryptoBuffer<byte> encodedPrivateKey = new(stackalloc byte[length]);
		Unsafe.SkipInit(out SM3Nonce<SM2Order> nonce);
		Unsafe.SkipInit(out FieldElement<SM2Order> k);
		Unsafe.SkipInit(out FieldElement<SM2Order> copy);

		try
		{
			ref readonly FieldElement<SM2Order> inverse = ref GetInverse(ref copy);
			ComputeE(message, id, hash);
			FieldElement<SM2Order>.ImportReduced(hash, out FieldElement<SM2Order> e);
			FieldElement<SM2Order>.Export(in e, hash);
			FieldElement<SM2Order>.Export(in privateKey, encodedPrivateKey.Span);
			nonce.Initialize(encodedPrivateKey.Span, hash, additionalData);
			FieldElement<SM2Order> r;
			FieldElement<SM2Order> s;

			do
			{
				nonce.Next(out k);
			}
			while (!TrySign(in inverse, in e, in k, out r, out s));

			return EcdsaEncoding<SM2Order>.Write(in r, in s, destination);
		}
		finally
		{
			nonce.Clear();
			k.ZeroMemory();
			copy.ZeroMemory();
		}
	}

	// GB/T 32918.2-2016, Sec. 7.1, for a signature in DER. Every input is public, so the products may take variable time.
	[SkipLocalsInit]
	internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> id)
	{
		// r and s lie in [1, n − 1], as GB/T 32918.2-2016, Sec. 7.1, B1 and B2, require.
		if (!EcdsaEncoding<SM2Order>.TryRead(signature, out FieldElement<SM2Order> r, out FieldElement<SM2Order> s))
		{
			return false;
		}

		FieldElement<SM2Order>.Add(in r, in s, out FieldElement<SM2Order> t);

		if (FieldElement<SM2Order>.IsZero(in t) is not 0)
		{
			return false;
		}

		Span<byte> hash = stackalloc byte[HashLength];
		ComputeE(message, id, hash);
		FieldElement<SM2Order>.ImportReduced(hash, out FieldElement<SM2Order> e);
		// R = (e + x1') mod n equals r just if x1' ≡ r − e (mod n).
		FieldElement<SM2Order>.Subtract(in r, in e, out FieldElement<SM2Order> difference);
		return MultiplyAddXModOrderEquals(in s, in t, in difference);
	}

	// Whether u1·G + u2·P is not the point at infinity and its x is r mod n, from the windows of P of SM2VerificationCurve from verification VerificationTableThreshold on, and from the products of EcdsaKey before. Every input is public. Not inlined, so that the frame of Verify keeps the size it has without the windows.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private bool MultiplyAddXModOrderEquals(in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, in FieldElement<SM2Order> r)
	{
		if (GetTable(ref _verificationTable, ref _verifications, VerificationTableThreshold) is not { } table)
		{
			return _key.MultiplyAddXModOrderEquals(in u1, in u2, in r);
		}

		ECVariableTimeGroup<SM2VerificationCurve, SM2CurveField, SM2Order>.MultiplyAdd(in u1, table, in u2, out JacobianPoint<SM2CurveField> result);
		return ECVariableTimeGroup<SM2Curve, SM2CurveField, SM2Order>.XModOrderEquals(in result, in r);
	}

	// One attempt as below, with (1 + d)⁻¹ from GetInverse.
	[SkipLocalsInit]
	internal bool TrySign(in FieldElement<SM2Order> e, in FieldElement<SM2Order> k, out FieldElement<SM2Order> r, out FieldElement<SM2Order> s)
	{
		Debug.Assert(HasPrivateKey);

		Unsafe.SkipInit(out FieldElement<SM2Order> copy);
		bool signed = TrySign(in GetInverse(ref copy), in e, in k, out r, out s);
		copy.ZeroMemory();
		return signed;
	}

	// One attempt of GB/T 32918.2-2016, Sec. 6.1, A4 to A6, with (1 + d)⁻¹·R, e mod n and the nonce k in [1, n − 1]: r = (e + x1) mod n for (x1, y1) = k·G, and s = (1 + d)⁻¹·(k − r·d) = (1 + d)⁻¹·(k + r) − r mod n. Returns false, so that the caller draws the next nonce, if r = 0, r + k = n or s = 0. Nothing branches on or indexes by k, e or (1 + d)⁻¹ before the result.
	private static bool TrySign(in FieldElement<SM2Order> inverse, in FieldElement<SM2Order> e, in FieldElement<SM2Order> k, out FieldElement<SM2Order> r, out FieldElement<SM2Order> s)
	{
		ECGroup<SM2Curve, SM2CurveField, SM2Order>.MultiplyBaseReduceX(in k, out FieldElement<SM2Order> x);
		FieldElement<SM2Order>.Add(in e, in x, out r);
		// 0 just if r + k = n.
		FieldElement<SM2Order>.Add(in k, in r, out FieldElement<SM2Order> sum);
		// (1 + d)⁻¹R · (k + r) · R⁻¹ = (1 + d)⁻¹·(k + r), in plain form.
		FieldElement<SM2Order>.Multiply(in inverse, in sum, out s);
		FieldElement<SM2Order>.Subtract(in s, in r, out s);
		ulong rejected = FieldElement<SM2Order>.IsZero(in r) | FieldElement<SM2Order>.IsZero(in sum) | FieldElement<SM2Order>.IsZero(in s);
		x.ZeroMemory();
		sum.ZeroMemory();
		return rejected is 0;
	}

	// GB/T 32918.4-2016, Sec. 6.1: C1 ‖ C3 ‖ C2 with C1 = k·G, (x2, y2) = k·P, t = KDF(x2 ‖ y2, klen), C2 = M ⊕ t and C3 = SM3(x2 ‖ M ‖ y2), for a k from fill, or if der is set the DER of SM2Cipher. destination is CiphertextOverhead bytes longer than plaintext, or if der is set at least SM2CipherDer.GetMaxLength long; plaintext is not empty and does not overlap it. If fill throws, destination remains unchanged. Returns the length.
	[SkipLocalsInit]
	internal int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> destination, Action<Span<byte>> fill, bool der)
	{
		Debug.Assert(!plaintext.IsEmpty && (der ? destination.Length >= SM2CipherDer.GetMaxLength(plaintext.Length) : destination.Length == CiphertextOverhead + plaintext.Length) && !plaintext.Overlaps(destination));

		Span<byte> c1 = stackalloc byte[PublicKeyLength];
		using CryptoBuffer<byte> point = new(stackalloc byte[PublicKeyLength]);
		using CryptoBuffer<byte> first = new(stackalloc byte[SM3KdfState.BlockLength]);
		Unsafe.SkipInit(out SM3KdfState kdf);

		try
		{
			DrawEphemeral(GetTable(ref _table, ref _encryptions, EncryptionTableThreshold), plaintext.Length, fill, c1, point.Span, ref kdf, first.Span);
			(int written, int hashOffset, int cipherTextOffset) = (CiphertextOverhead + plaintext.Length, PublicKeyLength, CiphertextOverhead);

			if (der)
			{
				written = SM2CipherDer.Write(c1, plaintext.Length, destination, out hashOffset, out cipherTextOffset);
			}
			else
			{
				c1.CopyTo(destination);
			}

			Seal(plaintext, in kdf, point.Span, first.Span, destination.Slice(hashOffset, HashLength), destination.Slice(cipherTextOffset, plaintext.Length));
			return written;
		}
		finally
		{
			kdf.Clear();
		}
	}

	// GB/T 32918.4-2016, Sec. 7.1, for a ciphertext C1 ‖ C3 ‖ C2 with C2 not empty: writes M' to the first C2.Length bytes of destination and returns true if C1 is a point on the curve, t is not all zero and C3 = SM3(x2 ‖ M' ‖ y2), which it compares in fixed time; otherwise returns false and writes nothing. destination may overlap ciphertext: M' goes there only after the last read of ciphertext.
	internal readonly bool Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> destination)
	{
		Debug.Assert(HasPrivateKey && ciphertext.Length > CiphertextOverhead && destination.Length >= ciphertext.Length - CiphertextOverhead);

		return Decrypt(ciphertext.Slice(0, PublicKeyLength), ciphertext.Slice(PublicKeyLength, HashLength), ciphertext.Slice(CiphertextOverhead), destination);
	}

	// As Decrypt, for C1 encoded, C3 and a C2 that is not empty.
	[SkipLocalsInit]
	internal readonly bool Decrypt(ReadOnlySpan<byte> c1, ReadOnlySpan<byte> c3, ReadOnlySpan<byte> c2, Span<byte> destination)
	{
		Debug.Assert(HasPrivateKey && !c2.IsEmpty && destination.Length >= c2.Length);

		// B1 and B2: C1 lies on the curve, which has cofactor 1, so S = C1 is not the point at infinity.
		if (!ECGroup<SM2Curve, SM2CurveField, SM2Order>.TryDecode(c1, out AffinePoint<SM2CurveField> point))
		{
			return false;
		}

		int length = c2.Length;
		using CryptoBuffer<byte> shared = new(stackalloc byte[PublicKeyLength]);
		using CryptoBuffer<byte> plaintext = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		Span<byte> hash = stackalloc byte[HashLength];
		Unsafe.SkipInit(out SM3KdfState kdf);
		Unsafe.SkipInit(out SM3Core digest);

		try
		{
			// B3: d·C1, which d in [1, n − 2] keeps from the point at infinity; the check never fails, but it keeps the bytes of shared, which SkipLocalsInit leaves as they were, out of the KDF if it did.
			if (!ECGroup<SM2Curve, SM2CurveField, SM2Order>.TryMultiplyEncode(in point, in _key.Key.PrivateScalar, shared.Span))
			{
				return false;
			}

			ReadOnlySpan<byte> x = shared.Span.Slice(1, HashLength);
			ReadOnlySpan<byte> y = shared.Span.Slice(1 + HashLength, HashLength);
			kdf.Initialize();
			kdf.Append(shared.Span.Slice(1));

			// B4 and B5: M' = C2 ⊕ t, and whether t, of length bytes, is all zero.
			ulong keyStream = kdf.Xor(1, c2, plaintext.Span);

			// B6: u = SM3(x2 ‖ M' ‖ y2).
			digest = HashCore.Create<SM3Core>();
			HashCore.Append(ref digest, x);
			HashCore.Append(ref digest, plaintext.Span);
			HashCore.Append(ref digest, y);
			HashCore.Finalize(ref digest, hash);

			if (LimbArithmetic.ZeroMask(keyStream) is not 0 | !FixedTime.Equals(hash, c3))
			{
				return false;
			}

			plaintext.Span.CopyTo(destination);
			return true;
		}
		finally
		{
			kdf.Clear();
			digest.ZeroMemory();
			hash.Clear();
		}
	}

	internal void Clear()
	{
		_key.Clear();
		_defaultZ = null;
		DropDerived();
	}

	// Whether d is n − 1, which SM2 leaves out of its private keys, as 1 + d then has no inverse: ulong.MaxValue or 0. n is odd, so n − 1 differs from n in limb 0 alone.
	private static ulong IsLast(in FieldElement<SM2Order> value)
	{
		ReadOnlySpan<ulong> limbs = FieldElement<SM2Order>.GetLimbs(in value);
		ReadOnlySpan<ulong> n = SM2Order.Modulus;
		return LimbArithmetic.ZeroMask(limbs[0] ^ n[0] - 1 | limbs[1] ^ n[1] | limbs[2] ^ n[2] | limbs[3] ^ n[3]);
	}

	// Rejects d = n − 1, which EcdsaKey accepts.
	private void RejectLast()
	{
		if (IsLast(in _key.Key.PrivateScalar) is not 0)
		{
			Clear();
			ThrowHelper.ThrowInvalidKey("source");
		}
	}

	// (1 + d)⁻¹·R, which the first signature computes, so that a key that only decrypts or exchanges keys never does. The thread that moves the stage from InverseMissing to InverseComputing is the only one that writes _inverse, and it sets InverseReady with a release once the value is whole; a signature reads _inverse only after it reads InverseReady with an acquire, so never in the middle of the write. A signature that comes while another computes the value computes it too, into copy, which the caller erases, and returns that.
	[UnscopedRef]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private ref readonly FieldElement<SM2Order> GetInverse(ref FieldElement<SM2Order> copy)
	{
		if (Volatile.Read(ref _inverseStage) is InverseReady)
		{
			return ref _inverse;
		}

		return ref PublishInverse(ref copy);
	}

	// GetInverse before the value is ready, out of line.
	[UnscopedRef]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private ref readonly FieldElement<SM2Order> PublishInverse(ref FieldElement<SM2Order> copy)
	{
		if (Interlocked.CompareExchange(ref _inverseStage, InverseComputing, InverseMissing) is InverseMissing)
		{
			ComputeInverse(in _key.Key.PrivateScalar, out _inverse);
			Volatile.Write(ref _inverseStage, InverseReady);
			return ref _inverse;
		}

		ComputeInverse(in _key.Key.PrivateScalar, out copy);
		return ref copy;
	}

	// (1 + d)·R is dR + R, and the inversion, in constant time, takes aR to a⁻¹R.
	[SkipLocalsInit]
	private static void ComputeInverse(in FieldElement<SM2Order> privateKey, out FieldElement<SM2Order> result)
	{
		Unsafe.SkipInit(out FieldElement<SM2Order> one);
		SM2Order.MontgomeryOne.CopyTo(MemoryMarshal.Cast<FieldElement<SM2Order>, ulong>(new Span<FieldElement<SM2Order>>(ref one)));
		FieldElement<SM2Order>.ToMontgomery(in privateKey, out FieldElement<SM2Order> sum);
		FieldElement<SM2Order>.Add(in sum, in one, out sum);
		FieldElement<SM2Order>.Invert(in sum, out result);
		sum.ZeroMemory();
	}

	// e = SM3(Z ‖ M) for the public key of the state.
	[SkipLocalsInit]
	private void ComputeE(ReadOnlySpan<byte> message, ReadOnlySpan<byte> id, Span<byte> destination)
	{
		Span<byte> z = stackalloc byte[HashLength];
		ComputeZ(id, z);
		SM3Core hash = HashCore.Create<SM3Core>();
		HashCore.Append(ref hash, z);
		HashCore.Append(ref hash, message);
		HashCore.Finalize(ref hash, destination);
	}

	// A1 to A5 of GB/T 32918.4-2016, Sec. 6.1: draws k until t = KDF(x2 ‖ y2, length) is not all zero, and leaves C1 = k·G in c1, k·P = (x2, y2) encoded in point, the KDF over x2 ‖ y2 in kdf and block 1 of t in first; k·P comes from table, the table of P, unless it is null. With cofactor 1 and P on the curve, S = P is not the point at infinity. Whether t is all zero follows from block 1 unless that is all zero too, which for 32 bytes or more has odds 2^−256, and only that and the retry branch on it.
	[SkipLocalsInit]
	private readonly void DrawEphemeral(ECPointTable<SM2Curve, SM2CurveField, SM2Order>? table, int length, Action<Span<byte>> fill, Span<byte> c1, Span<byte> point, ref SM3KdfState kdf, Span<byte> first)
	{
		Unsafe.SkipInit(out FieldElement<SM2Order> k);

		try
		{
			while (true)
			{
				ECKey<SM2Curve, SM2CurveField, SM2Order>.GeneratePrivateScalar(fill, out k);
				if (table is null)
				{
					ECGroup<SM2Curve, SM2CurveField, SM2Order>.MultiplyEncode(in _key.Key.PublicPoint, in k, c1, point);
				}
				else
				{
					ECGroup<SM2Curve, SM2CurveField, SM2Order>.MultiplyEncode(table, in k, c1, point);
				}

				kdf.Initialize();
				kdf.Append(point.Slice(1));
				kdf.WriteBlock(1, first);

				if (!kdf.IsZero(first, length))
				{
					return;
				}
			}
		}
		finally
		{
			k.ZeroMemory();
		}
	}

	// The windows of P for a key exchange with P as the static key of the peer, from KeyExchangeTableThreshold on, or null before.
	internal ECPointTable<SM2Curve, SM2CurveField, SM2Order>? GetExchangeTable()
	{
		return GetTable(ref _table, ref _exchanges, KeyExchangeTableThreshold);
	}

	// The windows of P in slot from operation threshold on of those that count counts, or null before. The count is atomic, so that operations at once still reach the threshold, and it stops once the windows are there, which another count may have built. Threads that reach it at once may each build the windows, but only the first to finish publishes them, the others discard theirs, and the products with and without them agree. Whether an operation takes the windows depends on the counts alone.
	private ECPointTable<TCurve, SM2CurveField, SM2Order>? GetTable<TCurve>(ref ECPointTable<TCurve, SM2CurveField, SM2Order>? slot, ref int count, int threshold) where TCurve : struct, IECCurve
	{
		if (slot is { } table)
		{
			return table;
		}

		return Interlocked.Increment(ref count) < threshold ? null : PublishTable(ref slot);
	}

	private ECPointTable<TCurve, SM2CurveField, SM2Order> PublishTable<TCurve>(ref ECPointTable<TCurve, SM2CurveField, SM2Order>? slot) where TCurve : struct, IECCurve
	{
		ECPointTable<TCurve, SM2CurveField, SM2Order> table = new(in _key.Key.PublicPoint);
		return Interlocked.CompareExchange(ref slot, table, null) ?? table;
	}

	// The windows follow from the public key and (1 + d)⁻¹ from the private key, so whatever replaces or clears the key drops them and erases the latter.
	private void DropDerived()
	{
		_inverse.ZeroMemory();
		_inverseStage = InverseMissing;
		_table = null;
		_verificationTable = null;
		_encryptions = 0;
		_verifications = 0;
		_exchanges = 0;
	}

	// A6 to A8: C3 = SM3(x2 ‖ M ‖ y2) and C2 = M ⊕ t, from block 1 of t in first and the next ones from kdf.
	[SkipLocalsInit]
	private static void Seal(ReadOnlySpan<byte> plaintext, in SM3KdfState kdf, ReadOnlySpan<byte> point, ReadOnlySpan<byte> first, Span<byte> c3, Span<byte> c2)
	{
		int length = plaintext.Length;
		SM3Core hash = HashCore.Create<SM3Core>();
		HashCore.Append(ref hash, point.Slice(1, HashLength));
		HashCore.Append(ref hash, plaintext);
		HashCore.Append(ref hash, point.Slice(1 + HashLength, HashLength));
		HashCore.Finalize(ref hash, c3);
		hash.ZeroMemory();
		FastUtils.Xor(first, plaintext, c2, Math.Min(SM3KdfState.BlockLength, length));

		if (length > SM3KdfState.BlockLength)
		{
			kdf.Xor(2, plaintext.Slice(SM3KdfState.BlockLength), c2.Slice(SM3KdfState.BlockLength));
		}
	}

	private static byte[] EncodeCurveParameters()
	{
		byte[] parameters = new byte[4 * SM2Field.ByteLength];
		Span<ulong> a = stackalloc ulong[SM2Field.LimbCount];
		SM2Field.Modulus.CopyTo(a);
		// p − 3 borrows nothing, as limb 0 of p is 2^64 − 1.
		a[0] -= 3;
		WriteBigEndian(a, parameters.AsSpan(0, SM2Field.ByteLength));
		WriteBigEndian(SM2Curve.B, parameters.AsSpan(SM2Field.ByteLength, SM2Field.ByteLength));
		WriteBigEndian(SM2Curve.GeneratorX, parameters.AsSpan(2 * SM2Field.ByteLength, SM2Field.ByteLength));
		WriteBigEndian(SM2Curve.GeneratorY, parameters.AsSpan(3 * SM2Field.ByteLength, SM2Field.ByteLength));
		return parameters;
	}

	private static void WriteBigEndian(ReadOnlySpan<ulong> limbs, Span<byte> destination)
	{
		for (int i = 0; i < limbs.Length; ++i)
		{
			BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(destination.Length - (i + 1) * sizeof(ulong)), limbs[i]);
		}
	}
}
