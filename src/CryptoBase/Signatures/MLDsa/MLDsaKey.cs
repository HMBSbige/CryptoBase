using CryptoBase.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace CryptoBase.Signatures.MLDsa;

// ML-DSA (FIPS 204) with the key expanded once: Â, t̂1 = NTT(t1 · 2^d) and, with the private key, ŝ1, ŝ2 and t̂0, each from Reduce
// and so below q in magnitude. Â and ŝ1 are expanded with the key, which needs them; ŝ2 and t̂0 wait for the first signature and t̂1 for the
// first verification, so that a key that is only generated and exported skips them. The encodings are kept for export.
internal struct MLDsaKey<TParameters> where TParameters : struct, IMLDsaParameters
{
	internal const int PrivateSeedLength = SeedLength;
	internal const int MuLength = HashLength;
	internal const int MaxContextLength = byte.MaxValue;

	// The length of ξ, ρ, K and rnd.
	private const int SeedLength = 32;

	// The length of ρ′, ρ″, tr and μ.
	private const int HashLength = 64;

	private const int N = MLDsaConstants.N;
	private const int T1Length = 320;
	private const int T0Length = 416;
	private const int SecretsOffset = 2 * SeedLength + HashLength;

	// M′ starts with 0 for ML-DSA and 1 for HashML-DSA (Algorithms 2 and 4).
	private const byte PureDomain = 0;
	private const byte PreHashDomain = 1;

	private const int MaxStreams = 8;

	// Five SHAKE128 blocks give 280 candidates, which rarely fall short of 256 coefficients; SampleRemaining squeezes the rest.
	private const int MatrixBlockLength = 168;
	private const int MatrixBlocks = 5;
	private const int MatrixSqueezeLength = MatrixBlocks * MatrixBlockLength;

	// Two SHAKE256 blocks give 544 candidates, which rarely fall short; ExpandSecrets squeezes the whole batch on for the rest.
	private const int StreamBlockLength = 136;
	private const int SecretSqueezeLength = 2 * StreamBlockLength;

	// ρ′ or ρ″ and a 2-byte nonce (Algorithms 33 and 34).
	private const int StreamInputLength = HashLength + sizeof(ushort);

	// Each row of Â followed by the entry of t̂1 in that row. Verification takes Â ∘ ẑ − t̂1 ∘ ĉ of a row in one MultiplyAccumulate.
	private int[]? _rows;

	// ŝ1, ŝ2 and t̂0, apart from the rows so that neither array of ML-DSA-87 reaches the large object heap.
	private int[]? _secrets;

	// pk = ρ ‖ SimpleBitPack(t1) (Algorithm 22) and sk = ρ ‖ K ‖ tr ‖ BitPack(s1) ‖ BitPack(s2) ‖ BitPack(t0) (Algorithm 24).
	private byte[]? _publicKey;
	private byte[]? _privateKey;

	private InlineArray64<byte> _tr;
	private InlineArray32<byte> _privateSeed;

	// Guards the transforms of the first signature and verification, and the erasure against them. Each flag is set last, with release semantics,
	// so that a caller that reads it set also reads the transformed polynomials without the lock.
	private Lock _gate;
	private bool _hasTransformedSecrets;
	private bool _hasPublicVector;

	internal static int PublicKeyLength => SeedLength + T1Length * K;

	internal static int PrivateKeyLength => SecretsOffset + (L + K) * EtaLength + T0Length * K;

	internal static int SignatureLength => CommitmentHashLength + L * ZLength + TParameters.Omega + K;

	internal static int SubjectPublicKeyInfoLength => KeyInfoDer.GetSubjectPublicKeyInfoLength(TParameters.AlgorithmIdentifier, PublicKeyLength);

	internal readonly int Pkcs8PrivateKeyLength
	{
		get
		{
			if (!HasPrivateKey)
			{
				ThrowHelper.ThrowMissingKey("private key");
			}

			return KeyInfoDer.GetPrivateKeyInfoLength(TParameters.AlgorithmIdentifier, PrivateKeyChoiceLength);
		}
	}

	internal bool HasPrivateSeed { readonly get; private set; }

	internal bool HasPrivateKey { readonly get; private set; }

	private static int K => TParameters.K;

	private static int L => TParameters.L;

	private static int Beta => TParameters.Tau * TParameters.Eta;

	private static int EtaLength => 32 * (TParameters.Eta is 2 ? 3 : 4);

	private static int ZLength => 32 * (1 + TParameters.Gamma1Bits);

	private static int W1Length => 32 * (TParameters.Gamma2 is MLDsaConstants.Gamma2Small ? 6 : 4);

	private static int CommitmentHashLength => TParameters.Lambda / 4;

	private static int T0Offset => SecretsOffset + (L + K) * EtaLength;

	// The tag of the seed form of the private key CHOICE (RFC 9881, Sec. 6). A property, so that each parameter set does not keep a copy.
	private static Asn1Tag SeedTag => new(TagClass.ContextSpecific, 0);

	// The ML-DSA-*-PrivateKey CHOICE of RFC 9881, Sec. 6: seed when the instance holds it, else expandedKey.
	private readonly int PrivateKeyChoiceLength => KeyInfoDer.GetEncodedLength(HasPrivateSeed ? SeedLength : PrivateKeyLength);

	private readonly Span<int> Rows => _rows.AsSpan();

	// s1 then s2, before the NTT.
	private readonly Span<int> Secrets => _secrets.AsSpan(0, (L + K) * N);

	private readonly Span<int> S1 => _secrets.AsSpan(0, L * N);

	private readonly Span<int> S2 => _secrets.AsSpan(L * N, K * N);

	private readonly Span<int> T0 => _secrets.AsSpan((L + K) * N, K * N);

	// s2 then t0, which the first signature transforms.
	private readonly Span<int> SigningSecrets => _secrets.AsSpan(L * N, 2 * K * N);

	private readonly ReadOnlySpan<byte> Rho => _publicKey.AsSpan(0, SeedLength);

	// K, the private random seed of signing.
	private readonly ReadOnlySpan<byte> SigningSeed => _privateKey.AsSpan(SeedLength, SeedLength);

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> Tr => _tr;

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> PrivateSeed => _privateSeed;

	[SkipLocalsInit]
	internal void GenerateKey()
	{
		using CryptoBuffer<byte> seed = new(stackalloc byte[SeedLength]);
		SystemRandom.Fill(seed.Span);
		GenerateKey<MLDsaKernelDispatch>(seed.Span);
	}

	internal void ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, SeedLength, nameof(source));
		GenerateKey<MLDsaKernelDispatch>(source);
	}

	// skDecode (Algorithm 25), rejecting s1 and s2 outside [−η, η], and t0 and tr that do not match ρ, s1 and s2.
	internal void ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		if (!ImportPrivateKey<MLDsaKernelDispatch>(source))
		{
			Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	// Every byte string of the length encodes a public key.
	internal void ImportPublicKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PublicKeyLength, nameof(source));
		ImportPublicKey<MLDsaKernelDispatch>(source);
	}

	internal void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		if (!KeyInfoDer.TryReadSubjectPublicKeyInfo(TParameters.AlgorithmIdentifier, source, out ReadOnlySpan<byte> publicKey) || publicKey.Length != PublicKeyLength)
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		ImportPublicKey<MLDsaKernelDispatch>(publicKey);
	}

	// A publicKey of OneAsymmetricKey must match the private key.
	internal void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		if (!KeyInfoDer.TryReadPrivateKeyInfo(TParameters.AlgorithmIdentifier, source, out ReadOnlySpan<byte> privateKey, out ReadOnlySpan<byte> publicKey)
			|| !ImportPrivateKeyChoice(privateKey)
			|| !publicKey.IsEmpty && !publicKey.SequenceEqual(_publicKey))
		{
			Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal readonly int ExportPrivateSeed(Span<byte> destination)
	{
		if (!HasPrivateSeed)
		{
			ThrowHelper.ThrowMissingKey("private seed");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SeedLength, nameof(destination));

		PrivateSeed.CopyTo(destination);
		return SeedLength;
	}

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateKeyLength, nameof(destination));

		_privateKey.CopyTo(destination);
		return PrivateKeyLength;
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PublicKeyLength, nameof(destination));

		_publicKey.CopyTo(destination);
		return PublicKeyLength;
	}

	internal readonly int ExportSubjectPublicKeyInfo(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SubjectPublicKeyInfoLength, nameof(destination));

		return KeyInfoDer.WriteSubjectPublicKeyInfo(TParameters.AlgorithmIdentifier, _publicKey, destination);
	}

	internal readonly int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, Pkcs8PrivateKeyLength, nameof(destination));

		int choiceLength = PrivateKeyChoiceLength;
		using CryptoBuffer<byte> choice = new(choiceLength);
		AsnWriter writer = new(AsnEncodingRules.DER, choiceLength);

		try
		{
			if (HasPrivateSeed)
			{
				writer.WriteOctetString(PrivateSeed, SeedTag);
			}
			else
			{
				writer.WriteOctetString(_privateKey);
			}

			writer.Encode(choice.Span);
		}
		finally
		{
			writer.Reset();
		}

		return KeyInfoDer.WritePrivateKeyInfo(TParameters.AlgorithmIdentifier, choice.Span, destination);
	}

	internal static bool Supports(SignatureAlgorithm algorithm)
	{
		return algorithm == TParameters.Algorithm;
	}

	internal static int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ThrowIfUnsupported(algorithm);
		return SignatureLength;
	}

	// The algorithm is ML-DSA with an empty context.
	internal int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ThrowIfUnsupported(algorithm);
		return Sign(message, default, destination);
	}

	internal bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ThrowIfUnsupported(algorithm);
		return Verify(message, signature, default);
	}

	// ML-DSA.Sign (Algorithm 2), hedged with rnd from the system.
	[SkipLocalsInit]
	internal int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> destination)
	{
		ThrowIfCannotSign(context, destination);

		using CryptoBuffer<byte> randomness = new(stackalloc byte[SeedLength]);
		SystemRandom.Fill(randomness.Span);
		return Sign<MLDsaKernelDispatch>(PureDomain, context, [], message, randomness.Span, destination);
	}

	// ML-DSA.Sign with a given rnd, for known-answer tests.
	internal int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> randomness, Span<byte> destination)
	{
		ThrowIfCannotSign(context, destination);
		ArgumentOutOfRangeException.ThrowIfNotEqual(randomness.Length, SeedLength, nameof(randomness));

		return Sign<MLDsaKernelDispatch>(PureDomain, context, [], message, randomness, destination);
	}

	// ML-DSA.Verify (Algorithm 3).
	[SkipLocalsInit]
	internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThan(context.Length, MaxContextLength, nameof(context));

		if (signature.Length != SignatureLength)
		{
			return false;
		}

		Span<byte> mu = stackalloc byte[MuLength];
		ComputeMu(PureDomain, context, [], message, mu);
		return VerifyMu<MLDsaKernelDispatch>(mu, signature);
	}

	// HashML-DSA.Sign (Algorithm 4) of a hash that the caller computed, hedged with rnd from the system.
	[SkipLocalsInit]
	internal int SignPreHash(ReadOnlySpan<byte> hash, Span<byte> destination, string hashAlgorithmOid, ReadOnlySpan<byte> context)
	{
		ArgumentNullException.ThrowIfNull(hashAlgorithmOid);

		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ReadOnlySpan<byte> oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, GetHashAlgorithmArc(hashAlgorithmOid, hash.Length)];
		ThrowIfCannotSign(context, destination);

		using CryptoBuffer<byte> randomness = new(stackalloc byte[SeedLength]);
		SystemRandom.Fill(randomness.Span);
		return Sign<MLDsaKernelDispatch>(PreHashDomain, context, oid, hash, randomness.Span, destination);
	}

	// HashML-DSA.Verify (Algorithm 5) of a hash that the caller computed.
	[SkipLocalsInit]
	internal bool VerifyPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, string hashAlgorithmOid, ReadOnlySpan<byte> context)
	{
		ArgumentNullException.ThrowIfNull(hashAlgorithmOid);

		ReadOnlySpan<byte> oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, GetHashAlgorithmArc(hashAlgorithmOid, hash.Length)];
		ArgumentOutOfRangeException.ThrowIfGreaterThan(context.Length, MaxContextLength, nameof(context));

		if (signature.Length != SignatureLength)
		{
			return false;
		}

		Span<byte> mu = stackalloc byte[MuLength];
		ComputeMu(PreHashDomain, context, oid, hash, mu);
		return VerifyMu<MLDsaKernelDispatch>(mu, signature);
	}

	// ML-DSA.Sign_internal (Algorithm 7) after μ, hedged with rnd from the system.
	[SkipLocalsInit]
	internal int SignMu(ReadOnlySpan<byte> mu, Span<byte> destination)
	{
		ThrowIfCannotSignMu(mu, destination);

		using CryptoBuffer<byte> randomness = new(stackalloc byte[SeedLength]);
		SystemRandom.Fill(randomness.Span);
		return SignMu<MLDsaKernelDispatch>(mu, randomness.Span, destination);
	}

	// ML-DSA.Sign_internal after μ with a given rnd, for known-answer tests.
	internal int SignMu(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> randomness, Span<byte> destination)
	{
		ThrowIfCannotSignMu(mu, destination);
		ArgumentOutOfRangeException.ThrowIfNotEqual(randomness.Length, SeedLength, nameof(randomness));

		return SignMu<MLDsaKernelDispatch>(mu, randomness, destination);
	}

	// ML-DSA.Verify_internal (Algorithm 8) after μ.
	internal bool VerifyMu(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> signature)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(mu.Length, MuLength, nameof(mu));

		return signature.Length == SignatureLength && VerifyMu<MLDsaKernelDispatch>(mu, signature);
	}

	// Waits out a first signature or verification that is transforming the key, which would otherwise write it back after the erasure.
	internal void Clear()
	{
		Lock? gate = _gate;
		gate?.Enter();

		try
		{
			_rows.AsSpan().ZeroMemory();
			_secrets.AsSpan().ZeroMemory();
			_publicKey.AsSpan().ZeroMemory();
			_privateKey.AsSpan().ZeroMemory();
			_tr.ZeroMemory();
			_privateSeed.ZeroMemory();
			HasPrivateSeed = false;
			HasPrivateKey = false;
			_hasTransformedSecrets = false;
			_hasPublicVector = false;
		}
		finally
		{
			gate?.Exit();
		}
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

	private readonly void ThrowIfCannotSignMu(ReadOnlySpan<byte> mu, Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfNotEqual(mu.Length, MuLength, nameof(mu));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SignatureLength, nameof(destination));
	}

	// The last arc of the OID of a hash that HashML-DSA may use, all under 2.16.840.1.101.3.4.2, checked against the hash length. The
	// collision strength of the hash, half its output, must be at least λ, which leaves out the 224-bit hashes.
	private static byte GetHashAlgorithmArc(string hashAlgorithmOid, int hashLength)
	{
		(byte arc, int length) = hashAlgorithmOid switch
		{
			"2.16.840.1.101.3.4.2.1" => ((byte)1, 32), // SHA-256
			"2.16.840.1.101.3.4.2.2" => ((byte)2, 48), // SHA-384
			"2.16.840.1.101.3.4.2.3" => ((byte)3, 64), // SHA-512
			"2.16.840.1.101.3.4.2.6" => ((byte)6, 32), // SHA-512/256
			"2.16.840.1.101.3.4.2.8" => ((byte)8, 32), // SHA3-256
			"2.16.840.1.101.3.4.2.9" => ((byte)9, 48), // SHA3-384
			"2.16.840.1.101.3.4.2.10" => ((byte)10, 64), // SHA3-512
			"2.16.840.1.101.3.4.2.11" => ((byte)11, 32), // SHAKE128 with 256 bits of output
			"2.16.840.1.101.3.4.2.12" => ((byte)12, 64), // SHAKE256 with 512 bits of output
			_ => ((byte)0, 0)
		};

		if (arc is 0 || 4 * length < TParameters.Lambda)
		{
			ThrowHelper.ThrowUnsupportedHashAlgorithm(nameof(hashAlgorithmOid));
		}

		if (hashLength != length)
		{
			ThrowHelper.ThrowHashLengthMismatch("hash");
		}

		return arc;
	}

	// Every array is written in full before it is read, so none needs to start zeroed.
	private void Allocate(bool hasPrivateKey)
	{
		if (hasPrivateKey)
		{
			_secrets = GC.AllocateUninitializedArray<int>((L + 2 * K) * N);
			_privateKey = GC.AllocateUninitializedArray<byte>(PrivateKeyLength);
		}

		_rows = GC.AllocateUninitializedArray<int>(K * (L + 1) * N);
		_publicKey = GC.AllocateUninitializedArray<byte>(PublicKeyLength);
		_gate = new Lock();
	}

	// ML-DSA.KeyGen_internal (Algorithm 6).
	[SkipLocalsInit]
	private void GenerateKey<TKernel>(ReadOnlySpan<byte> seed) where TKernel : IMLDsaKernel
	{
		Allocate(true);
		Span<byte> publicKey = _publicKey;
		Span<byte> privateKey = _privateKey;

		// (ρ, ρ′, K) ← H(ξ ‖ IntegerToBytes(k, 1) ‖ IntegerToBytes(l, 1), 128).
		using CryptoBuffer<byte> expanded = new(stackalloc byte[2 * SeedLength + HashLength]);
		ReadOnlySpan<byte> dimensions = [(byte)K, (byte)L];
		Shake256(seed, dimensions, [], expanded.Span);
		ReadOnlySpan<byte> rho = expanded.Span.Slice(0, SeedLength);
		rho.CopyTo(publicKey);
		rho.CopyTo(privateKey);
		expanded.Span.Slice(SeedLength + HashLength, SeedLength).CopyTo(privateKey.Slice(SeedLength));

		ExpandMatrix<TKernel>([]);
		ExpandSecrets<TKernel>(expanded.Span.Slice(SeedLength, HashLength), Secrets);
		EncodeSecrets<TKernel>(privateKey.Slice(SecretsOffset));
		ComputePublicVector<TKernel>(publicKey.Slice(SeedLength), privateKey.Slice(T0Offset));

		// tr ← H(pk, 64).
		Shake256(publicKey, [], [], _tr);
		Tr.CopyTo(privateKey.Slice(2 * SeedLength));
		seed.CopyTo(_privateSeed);
		HasPrivateSeed = true;
		HasPrivateKey = true;
	}

	// Must not stop at the first invalid polynomial.
	[SkipLocalsInit]
	private bool ImportPrivateKey<TKernel>(ReadOnlySpan<byte> source) where TKernel : IMLDsaKernel
	{
		int etaLength = EtaLength;
		Allocate(true);
		source.CopyTo(_privateKey);
		source.Slice(0, SeedLength).CopyTo(_publicKey);
		source.Slice(2 * SeedLength, HashLength).CopyTo(_tr);

		Span<int> secrets = Secrets;
		bool valid = true;

		for (int i = 0; i < L + K; ++i)
		{
			valid &= TKernel.DecodeEta(source.Slice(SecretsOffset + i * etaLength, etaLength), secrets.Slice(i * N, N), TParameters.Eta);
		}

		ExpandMatrix<TKernel>([]);
		using CryptoBuffer<byte> t0 = new(T0Length * K);
		ComputePublicVector<TKernel>(_publicKey.AsSpan(SeedLength), t0.Span);

		Span<byte> tr = stackalloc byte[HashLength];
		Shake256(_publicKey, [], [], tr);
		valid &= FixedTime.Equals(t0.Span, source.Slice(T0Offset, T0Length * K));
		valid &= FixedTime.Equals(tr, Tr);
		HasPrivateKey = valid;
		return valid;
	}

	private void ImportPublicKey<TKernel>(ReadOnlySpan<byte> source) where TKernel : IMLDsaKernel
	{
		Allocate(false);
		source.CopyTo(_publicKey);
		ExpandMatrix<TKernel>(source);
	}

	// The tag tells the CHOICE (RFC 9881, Sec. 6); seed and expandedKey together must agree (Sec. 8.2).
	private bool ImportPrivateKeyChoice(ReadOnlySpan<byte> source)
	{
		try
		{
			Asn1Tag tag = Asn1Tag.Decode(source, out _);
			ReadOnlySpan<byte> seed;
			ReadOnlySpan<byte> expandedKey;
			int consumed;

			if (tag == SeedTag)
			{
				if (!TryReadOctetString(source, SeedTag, SeedLength, out seed, out consumed) || consumed != source.Length)
				{
					return false;
				}

				GenerateKey<MLDsaKernelDispatch>(seed);
				return true;
			}

			if (tag == Asn1Tag.PrimitiveOctetString)
			{
				return TryReadOctetString(source, Asn1Tag.PrimitiveOctetString, PrivateKeyLength, out expandedKey, out consumed)
					&& consumed == source.Length
					&& ImportPrivateKey<MLDsaKernelDispatch>(expandedKey);
			}

			if (tag != Asn1Tag.Sequence)
			{
				return false;
			}

			AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out int offset, out int length, out consumed);
			ReadOnlySpan<byte> contents = source.Slice(offset, length);

			if (consumed != source.Length || !TryReadOctetString(contents, Asn1Tag.PrimitiveOctetString, SeedLength, out seed, out consumed))
			{
				return false;
			}

			contents = contents.Slice(consumed);

			if (!TryReadOctetString(contents, Asn1Tag.PrimitiveOctetString, PrivateKeyLength, out expandedKey, out consumed) || consumed != contents.Length)
			{
				return false;
			}

			GenerateKey<MLDsaKernelDispatch>(seed);
			return FixedTime.Equals(_privateKey, expandedKey);
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	private static bool TryReadOctetString(ReadOnlySpan<byte> source, Asn1Tag tag, int length, out ReadOnlySpan<byte> value, out int consumed)
	{
		return AsnDecoder.TryReadPrimitiveOctetString(source, AsnEncodingRules.DER, out value, out consumed, tag) && value.Length == length;
	}

	// BitPack(s, η, η) of s1 then s2 (Algorithm 24).
	private readonly void EncodeSecrets<TKernel>(Span<byte> destination) where TKernel : IMLDsaKernel
	{
		int etaLength = EtaLength;
		Span<int> secrets = Secrets;

		for (int i = 0; i < L + K; ++i)
		{
			TKernel.EncodeEta(secrets.Slice(i * N, N), destination.Slice(i * etaLength, etaLength), TParameters.Eta);
		}
	}

	// t ← NTT⁻¹(Â ∘ NTT(s1)) + s2 and (t1, t0) ← Power2Round(t) (Algorithm 6) row by row, into the encodings
	// of t1 and t0 and into T0. s1 ends transformed.
	[SkipLocalsInit]
	private readonly void ComputePublicVector<TKernel>(Span<byte> t1Encoded, Span<byte> t0Encoded) where TKernel : IMLDsaKernel
	{
		int l = L;
		Span<int> s1 = S1;
		Span<int> s2 = S2;
		Span<int> t0 = T0;
		TransformVector<TKernel>(s1);

		using CryptoBuffer<int> polynomials = new(stackalloc int[2 * N]);
		Span<int> t = polynomials.Span.Slice(0, N);
		Span<int> t1 = polynomials.Span.Slice(N, N);

		for (int i = 0; i < K; ++i)
		{
			Span<int> low = t0.Slice(i * N, N);
			TKernel.MultiplyAccumulate(Rows.Slice(i * (l + 1) * N, l * N), s1, t, l);
			TKernel.InverseNtt(t);
			TKernel.Add(t, s2.Slice(i * N, N), t);
			TKernel.Power2Round(t, t1, low);
			TKernel.EncodeT1(t1, t1Encoded.Slice(i * T1Length, T1Length));
			TKernel.EncodeT0(low, t0Encoded.Slice(i * T0Length, T0Length));
		}
	}

	// ŝ2 and t̂0, in place under the lock: a caller that reads the flag clear waits here rather than read them half transformed.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void TransformSecrets<TKernel>() where TKernel : IMLDsaKernel
	{
		lock (_gate)
		{
			if (!_hasTransformedSecrets)
			{
				TransformVector<TKernel>(SigningSecrets);
				Volatile.Write(ref _hasTransformedSecrets, true);
			}
		}
	}

	// t̂1 = NTT(t1 · 2^d) (Algorithm 8) from the encoding in pk, entry i after row i of Â, in place under the lock as TransformSecrets does.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void DecodePublicVector<TKernel>() where TKernel : IMLDsaKernel
	{
		lock (_gate)
		{
			if (!_hasPublicVector)
			{
				DecodePublicVectorCore<TKernel>();
				Volatile.Write(ref _hasPublicVector, true);
			}
		}
	}

	private readonly void DecodePublicVectorCore<TKernel>() where TKernel : IMLDsaKernel
	{
		int l = L;
		ReadOnlySpan<byte> encoded = _publicKey.AsSpan(SeedLength);
		Span<int> rows = Rows;

		for (int i = 0; i < K; ++i)
		{
			Span<int> polynomial = rows.Slice((i * (l + 1) + l) * N, N);
			TKernel.DecodeT1(encoded.Slice(i * T1Length, T1Length), polynomial);
			TKernel.Ntt(polynomial);
			TKernel.Reduce(polynomial);
		}
	}

	private static void TransformVector<TKernel>(Span<int> vector) where TKernel : IMLDsaKernel
	{
		for (int i = 0; i < vector.Length; i += N)
		{
			Span<int> polynomial = vector.Slice(i, N);
			TKernel.Ntt(polynomial);
			TKernel.Reduce(polynomial);
		}
	}

	// μ ← H(tr ‖ M′, 64) (Algorithm 7) with M′ = IntegerToBytes(domain, 1) ‖ IntegerToBytes(|ctx|, 1) ‖ ctx ‖ oid ‖ message, oid empty
	// for ML-DSA (Algorithm 2) and that of the hash for HashML-DSA (Algorithm 4).
	private readonly void ComputeMu(byte domain, ReadOnlySpan<byte> context, ReadOnlySpan<byte> oid, ReadOnlySpan<byte> message, Span<byte> mu)
	{
		ReadOnlySpan<byte> header = [domain, (byte)context.Length];
		KeccakSponge<KeccakRate136> sponge = default;
		sponge.Absorb(Tr);
		sponge.Absorb(header);
		sponge.Absorb(context);
		sponge.Absorb(oid);
		sponge.Absorb(message);
		sponge.Pad(KeccakDomainSeparator.Shake);
		sponge.Squeeze(mu.Slice(0, MuLength));
	}

	// The message is read in full before the signature is written, so the two may overlap.
	[SkipLocalsInit]
	private int Sign<TKernel>(byte domain, ReadOnlySpan<byte> context, ReadOnlySpan<byte> oid, ReadOnlySpan<byte> message, ReadOnlySpan<byte> randomness, Span<byte> destination) where TKernel : IMLDsaKernel
	{
		Span<byte> mu = stackalloc byte[MuLength];
		ComputeMu(domain, context, oid, message, mu);
		return SignMu<TKernel>(mu, randomness, destination);
	}

	// ML-DSA.Sign_internal (Algorithm 7) after μ. w − ⟨⟨cs2⟩⟩ has the high bits w1 and the low bits w0 − ⟨⟨cs2⟩⟩ when those are below
	// γ2 − β, so the checks and the hints take w0 − ⟨⟨cs2⟩⟩. An attempt stops at the first polynomial that fails a check: each check scans
	// its whole polynomial, and which one fails is independent of the key (Dilithium specification, Sec. 5.5). Where a batch of ExpandMask
	// has a free lane, c̃ of an attempt is hashed in it while the batch expands y of the next attempt, which goes to waste after the last;
	// with fewer than four lanes, the batches of that y cost more than the hash saves. μ is read in full before the signature is written.
	[SkipLocalsInit]
	private int SignMu<TKernel>(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> randomness, Span<byte> signature) where TKernel : IMLDsaKernel
	{
		int k = K;
		int l = L;
		int gamma2 = TParameters.Gamma2;
		int beta = Beta;
		int zLength = ZLength;
		int w1Length = W1Length;
		int commitmentHashLength = CommitmentHashLength;

		if (!Volatile.Read(in _hasTransformedSecrets))
		{
			TransformSecrets<TKernel>();
		}

		Span<int> s1 = S1;
		Span<int> s2 = S2;
		Span<int> t0 = T0;

		// ρ″ ← H(K ‖ rnd ‖ μ, 64).
		using CryptoBuffer<byte> rhoPrimePrime = new(stackalloc byte[HashLength]);
		Shake256(SigningSeed, randomness, mu, rhoPrimePrime.Span);

		bool pipelined = KeccakP1600Batch.MaxLanes >= KeccakP1600Times4.Lanes && l % KeccakP1600Batch.MaxLanes is not 0;
		using CryptoBuffer<int> polynomials = new((3 * l + 2 * k + 2) * N);
		Span<int> y = polynomials.Span.Slice(0, l * N);
		Span<int> nextY = polynomials.Span.Slice(l * N, l * N);
		Span<int> z = polynomials.Span.Slice(2 * l * N, l * N);
		Span<int> low = polynomials.Span.Slice(3 * l * N, k * N);
		Span<int> high = polynomials.Span.Slice((3 * l + k) * N, k * N);
		Span<int> c = polynomials.Span.Slice((3 * l + 2 * k) * N, N);
		Span<int> product = polynomials.Span.Slice((3 * l + 2 * k + 1) * N, N);

		// μ ‖ w1Encode(w1).
		using CryptoBuffer<byte> commitment = new(stackalloc byte[MuLength + k * w1Length]);
		mu.CopyTo(commitment.Span);
		Span<byte> commitmentHash = stackalloc byte[commitmentHashLength];

		// y ← ExpandMask(ρ″, κ).
		ExpandMask<TKernel>(rhoPrimePrime.Span, 0, y, [], []);

		for (int kappa = 0; ; kappa += l)
		{
			// w ← NTT⁻¹(Â ∘ NTT(y)), then w1 and w0 by Decompose; z holds ŷ meanwhile.
			y.CopyTo(z);

			for (int r = 0; r < l; ++r)
			{
				TKernel.Ntt(z.Slice(r * N, N));
			}

			for (int i = 0; i < k; ++i)
			{
				Span<int> w1 = high.Slice(i * N, N);
				TKernel.MultiplyAccumulate(Rows.Slice(i * (l + 1) * N, l * N), z, product, l);
				TKernel.InverseNtt(product);
				TKernel.Decompose(product, w1, low.Slice(i * N, N), gamma2);
				TKernel.EncodeW1(w1, commitment.Span.Slice(MuLength + i * w1Length, w1Length), gamma2);
			}

			// c̃ ← H(μ ‖ w1Encode(w1), λ / 4), ĉ ← NTT(SampleInBall(c̃)).
			if (pipelined)
			{
				ExpandMask<TKernel>(rhoPrimePrime.Span, kappa + l, nextY, commitment.Span, commitmentHash);
			}
			else
			{
				Shake256(commitment.Span, [], [], commitmentHash);
			}

			SampleInBall(commitmentHash, c, 1);
			TKernel.Ntt(c);

			// z ← y + ⟨⟨cs1⟩⟩ with ‖z‖∞ < γ1 − β.
			for (int r = 0; r < l; ++r)
			{
				Span<int> polynomial = z.Slice(r * N, N);
				TKernel.MultiplyAccumulate(s1.Slice(r * N, N), c, product, 1);
				TKernel.InverseNtt(product);
				if (TKernel.AddReduceExceedsBound(product, y.Slice(r * N, N), polynomial, (1 << TParameters.Gamma1Bits) - beta))
				{
					goto reject;
				}
			}

			// ‖w0 − ⟨⟨cs2⟩⟩‖∞ < γ2 − β, which low then holds.
			for (int i = 0; i < k; ++i)
			{
				Span<int> polynomial = low.Slice(i * N, N);
				TKernel.MultiplyAccumulate(s2.Slice(i * N, N), c, product, 1);
				TKernel.InverseNtt(product);
				if (TKernel.SubtractReduceExceedsBound(polynomial, product, polynomial, gamma2 - beta))
				{
					goto reject;
				}
			}

			// ‖⟨⟨ct0⟩⟩‖∞ < γ2, and at most ω hints for w0 − ⟨⟨cs2⟩⟩ + ⟨⟨ct0⟩⟩, which low then holds.
			int hints = 0;

			for (int i = 0; i < k; ++i)
			{
				Span<int> polynomial = low.Slice(i * N, N);
				TKernel.MultiplyAccumulate(t0.Slice(i * N, N), c, product, 1);
				TKernel.InverseNtt(product);
				if (TKernel.ReduceExceedsBound(product, gamma2))
				{
					goto reject;
				}

				TKernel.Add(polynomial, product, polynomial);
				hints += TKernel.MakeHint(polynomial, high.Slice(i * N, N), polynomial, gamma2);
			}

			if (hints <= TParameters.Omega)
			{
				break;
			}

		reject:
			if (pipelined)
			{
				Span<int> expanded = y;
				y = nextY;
				nextY = expanded;
			}
			else
			{
				ExpandMask<TKernel>(rhoPrimePrime.Span, kappa + l, y, [], []);
			}
		}

		// sigEncode (Algorithm 26).
		commitmentHash.CopyTo(signature);

		for (int r = 0; r < l; ++r)
		{
			TKernel.EncodeZ(z.Slice(r * N, N), signature.Slice(commitmentHashLength + r * zLength, zLength), TParameters.Gamma1Bits);
		}

		EncodeHints(low, signature.Slice(commitmentHashLength + l * zLength, TParameters.Omega + k));
		return SignatureLength;
	}

	// ML-DSA.Verify_internal (Algorithm 8) after μ. The signature is public, so it may steer branches.
	[SkipLocalsInit]
	private bool VerifyMu<TKernel>(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> signature) where TKernel : IMLDsaKernel
	{
		if (!Volatile.Read(in _hasPublicVector))
		{
			DecodePublicVector<TKernel>();
		}

		int k = K;
		int l = L;
		int gamma2 = TParameters.Gamma2;
		int zLength = ZLength;
		int w1Length = W1Length;
		int commitmentHashLength = CommitmentHashLength;
		int omega = TParameters.Omega;

		// sigDecode (Algorithm 27).
		ReadOnlySpan<byte> commitmentHash = signature.Slice(0, commitmentHashLength);
		ReadOnlySpan<byte> encodedZ = signature.Slice(commitmentHashLength, l * zLength);
		ReadOnlySpan<byte> hints = signature.Slice(commitmentHashLength + l * zLength, omega + k);

		if (!AreHintsValid(hints))
		{
			return false;
		}

		using CryptoBuffer<int> polynomials = new((l + 3) * N);
		Span<int> z = polynomials.Span.Slice(0, l * N);
		Span<int> c = polynomials.Span.Slice(l * N, N);
		Span<int> w = polynomials.Span.Slice((l + 1) * N, N);
		Span<int> hint = polynomials.Span.Slice((l + 2) * N, N);

		// ‖z‖∞ < γ1 − β, checked first.
		for (int r = 0; r < l; ++r)
		{
			Span<int> polynomial = z.Slice(r * N, N);
			TKernel.DecodeZ(encodedZ.Slice(r * zLength, zLength), polynomial, TParameters.Gamma1Bits);

			if (TKernel.ExceedsBound(polynomial, (1 << TParameters.Gamma1Bits) - Beta))
			{
				return false;
			}

			TKernel.Ntt(polynomial);
		}

		// −c after z, so that a row of Â and t̂1 with ẑ and −ĉ makes one MultiplyAccumulate.
		SampleInBall(commitmentHash, c, -1);
		TKernel.Ntt(c);

		// w′Approx ← NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t1 · 2^d)), w1′ ← UseHint(h, w′Approx).
		ReadOnlySpan<int> rows = Rows;
		ReadOnlySpan<int> vector = polynomials.Span.Slice(0, (l + 1) * N);
		Span<byte> commitment = stackalloc byte[k * w1Length];
		int index = 0;

		for (int i = 0; i < k; ++i)
		{
			TKernel.MultiplyAccumulate(rows.Slice(i * (l + 1) * N, (l + 1) * N), vector, w, l + 1);
			TKernel.InverseNtt(w);

			// HintBitUnpack (Algorithm 21) of row i.
			hint.Clear();

			for (int end = hints[omega + i]; index < end; ++index)
			{
				hint[hints[index]] = 1;
			}

			TKernel.UseHint(w, hint, w, gamma2);
			TKernel.EncodeW1(w, commitment.Slice(i * w1Length, w1Length), gamma2);
		}

		// c̃′ ← H(μ ‖ w1Encode(w1′), λ / 4), compared with c̃.
		Span<byte> expected = stackalloc byte[commitmentHashLength];
		Shake256(mu, commitment, [], expected);
		return expected.SequenceEqual(commitmentHash);
	}

	// The checks of HintBitUnpack (Algorithm 21): each count in [the previous one, ω], the positions of a polynomial
	// strictly increasing, and zeros after the last.
	private static bool AreHintsValid(ReadOnlySpan<byte> hints)
	{
		int omega = TParameters.Omega;
		int index = 0;

		for (int i = 0; i < K; ++i)
		{
			int end = hints[omega + i];

			if (end < index || end > omega)
			{
				return false;
			}

			for (int first = index; index < end; ++index)
			{
				if (index > first && hints[index - 1] >= hints[index])
				{
					return false;
				}
			}
		}

		return !hints.Slice(index, omega - index).ContainsAnyExcept((byte)0);
	}

	// HintBitPack (Algorithm 20). The hints are part of the signature, so they may steer branches.
	private static void EncodeHints(ReadOnlySpan<int> hints, Span<byte> destination)
	{
		int omega = TParameters.Omega;
		destination.Slice(0, omega).Clear();
		int index = 0;

		for (int i = 0; i < K; ++i)
		{
			ReadOnlySpan<int> hint = hints.Slice(i * N, N);

			for (int j = 0; j < N; ++j)
			{
				if (hint[j] is not 0)
				{
					destination[index++] = (byte)j;
				}
			}

			destination[omega + i] = (byte)index;
		}
	}

	// SampleInBall (Algorithm 29) of the whole of c̃, times sign in {−1, 1}. The squeezed bytes steer the rejection loop, as in the algorithm.
	[SkipLocalsInit]
	private static void SampleInBall(ReadOnlySpan<byte> commitmentHash, Span<int> c, int sign)
	{
		KeccakSponge<KeccakRate136> sponge = default;
		sponge.Absorb(commitmentHash);
		sponge.Pad(KeccakDomainSeparator.Shake);

		using CryptoBuffer<byte> block = new(stackalloc byte[StreamBlockLength]);
		sponge.Squeeze(block.Span);
		ulong signs = BinaryPrimitives.ReadUInt64LittleEndian(block.Span);
		int position = sizeof(ulong);
		c.Clear();

		for (int i = N - TParameters.Tau; i < N; ++i)
		{
			int j;

			do
			{
				if (position >= StreamBlockLength)
				{
					sponge.Squeeze(block.Span);
					position = 0;
				}

				j = block.Span[position++];
			}
			while (j > i);

			c[i] = c[j];
			c[j] = sign - 2 * sign * (int)(signs & 1);
			signs >>= 1;
		}

		sponge.ZeroMemory();
	}

	// ExpandA (Algorithm 32): entry r · l + s, Â[r, s] = RejNTTPoly(ρ ‖ s ‖ r), is polynomial r · (l + 1) + s of Rows.
	// Given the public key, tr ← H(pk, 64) is absorbed a block at a time in a free lane of the batches, as a batch permutation costs little
	// more than a single one; a batch gives up a stream for it only while it fills every permutation of the batch.
	[SkipLocalsInit]
	private void ExpandMatrix<TKernel>(ReadOnlySpan<byte> publicKey) where TKernel : IMLDsaKernel
	{
		int l = L;
		int entries = K * l;
		Span<int> rows = Rows;
		Span<ushort> suffixes = stackalloc ushort[MaxStreams];
		Span<byte> outputs = stackalloc byte[MaxStreams * MatrixSqueezeLength];
		Unsafe.SkipInit(out KeccakBatchSponge<KeccakRate168> sponge);
		KeccakSponge<KeccakRate136> hash = default;
		int hashed = 0;

		// The permutations left to absorb the rest of publicKey and the padding.
		int hashSteps = publicKey.IsEmpty ? 0 : publicKey.Length / StreamBlockLength + 1;

		for (int first = 0; first < entries; first += sponge.Count)
		{
			int streams = entries - first;
			int guests = 0;

			if (hashSteps >= MatrixBlocks)
			{
				streams = Math.Min(streams, Math.Max(KeccakP1600Batch.MaxLanes - 1, 1));
				guests = 1;
			}

			int group = Math.Min(streams, MaxStreams);

			for (int j = 0; j < group; ++j)
			{
				int entry = first + j;
				suffixes[j] = (ushort)(entry % l | entry / l << 8);
			}

			sponge.ResetWithGuests(streams, guests, Rho, suffixes.Slice(0, group), sizeof(ushort), KeccakDomainSeparator.Shake);
			int count = sponge.Count;
			Debug.Assert(count <= MaxStreams);
			Span<byte> groupOutputs = outputs.Slice(0, count * MatrixSqueezeLength);

			for (int block = 0; block < MatrixBlocks; ++block)
			{
				if (hashSteps > 0 && sponge.FreeLanes > 0)
				{
					hashed += hash.AbsorbBlock(publicKey.Slice(hashed), KeccakDomainSeparator.Shake);
					sponge.Permute(new Span<KeccakSponge<KeccakRate136>>(ref hash));
					--hashSteps;
				}

				sponge.Squeeze(groupOutputs, block * MatrixBlockLength, MatrixBlockLength);
			}

			for (int j = 0; j < count; ++j)
			{
				int entry = first + j;
				Span<int> polynomial = rows.Slice((entry + entry / l) * N, N);
				int sampled = TKernel.RejectSample(groupOutputs.Slice(j * MatrixSqueezeLength, MatrixSqueezeLength), polynomial);

				if (sampled < N)
				{
					SampleRemaining<TKernel>(sponge.ExtractLane(j), polynomial, sampled);
				}
			}
		}

		if (!publicKey.IsEmpty)
		{
			if (hashSteps > 0)
			{
				hash.Absorb(publicKey.Slice(hashed));
				hash.Pad(KeccakDomainSeparator.Shake);
			}

			hash.Squeeze(_tr);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void SampleRemaining<TKernel>(KeccakSponge<KeccakRate168> sponge, Span<int> polynomial, int sampled) where TKernel : IMLDsaKernel
	{
		Span<byte> block = stackalloc byte[MatrixBlockLength];

		while (sampled < N)
		{
			sponge.Squeeze(block);
			sampled += TKernel.RejectSample(block, polynomial.Slice(sampled));
		}
	}

	// ExpandS (Algorithm 33): s1 from nonces 0 to l − 1 and s2 from l to l + k − 1, into secrets in that order. A stream that falls short
	// squeezes on with its whole batch, so that no copy of its state, from which ρ′ could be recovered, is left outside the batch.
	[SkipLocalsInit]
	private static void ExpandSecrets<TKernel>(ReadOnlySpan<byte> seed, Span<int> secrets) where TKernel : IMLDsaKernel
	{
		int streams = L + K;
		using CryptoBuffer<byte> inputs = new(stackalloc byte[MaxStreams * StreamInputLength]);
		using CryptoBuffer<byte> outputs = new(stackalloc byte[MaxStreams * SecretSqueezeLength]);
		Span<int> sampled = stackalloc int[MaxStreams];
		Unsafe.SkipInit(out KeccakBatchSponge<KeccakRate136> sponge);

		for (int done = 0; done < streams; done += sponge.Count)
		{
			AbsorbSeeds(ref sponge, seed, done, streams - done, 0, inputs.Span);
			int count = sponge.Count;
			Span<byte> groupOutputs = outputs.Span.Slice(0, count * SecretSqueezeLength);
			Span<int> groupSampled = sampled.Slice(0, count);
			sponge.Squeeze(groupOutputs);

			for (int j = 0; j < count; ++j)
			{
				groupSampled[j] = TKernel.RejectEta(groupOutputs.Slice(j * SecretSqueezeLength, SecretSqueezeLength), secrets.Slice((done + j) * N, N), TParameters.Eta);
			}

			while (groupSampled.ContainsAnyExcept(N))
			{
				Span<byte> blocks = outputs.Span.Slice(0, count * StreamBlockLength);
				sponge.Squeeze(blocks);

				for (int j = 0; j < count; ++j)
				{
					int filled = groupSampled[j];
					groupSampled[j] += TKernel.RejectEta(blocks.Slice(j * StreamBlockLength, StreamBlockLength), secrets.Slice((done + j) * N + filled, N - filled), TParameters.Eta);
				}
			}
		}

		sponge.ZeroMemory();
	}

	// ExpandMask (Algorithm 34): y[r] ← BitUnpack(H(ρ″ ‖ IntegerToBytes(κ + r, 2), 32c), γ1 − 1, γ1) with c = 1 + log2 γ1. Given a
	// message, H(message, hash.Length) is absorbed a block at a time in a free lane of the batches.
	[SkipLocalsInit]
	internal static void ExpandMask<TKernel>(ReadOnlySpan<byte> seed, int kappa, Span<int> y, ReadOnlySpan<byte> message, Span<byte> hash) where TKernel : IMLDsaKernel
	{
		int zLength = ZLength;
		using CryptoBuffer<byte> inputs = new(stackalloc byte[MaxStreams * StreamInputLength]);
		using CryptoBuffer<byte> outputs = new(stackalloc byte[MaxStreams * zLength]);
		Unsafe.SkipInit(out KeccakBatchSponge<KeccakRate136> sponge);
		KeccakSponge<KeccakRate136> guest = default;
		int hashed = 0;

		// The permutations left to absorb the rest of message and the padding.
		int hashSteps = message.IsEmpty ? 0 : message.Length / StreamBlockLength + 1;

		for (int done = 0; done < L; done += sponge.Count)
		{
			AbsorbSeeds(ref sponge, seed, kappa + done, L - done, hashSteps > 0 ? 1 : 0, inputs.Span);
			int count = sponge.Count;
			Span<byte> groupOutputs = outputs.Span.Slice(0, count * zLength);

			for (int offset = 0; offset < zLength; offset += StreamBlockLength)
			{
				if (hashSteps > 0 && sponge.FreeLanes > 0)
				{
					hashed += guest.AbsorbBlock(message.Slice(hashed), KeccakDomainSeparator.Shake);
					sponge.Permute(new Span<KeccakSponge<KeccakRate136>>(ref guest));
					--hashSteps;
				}

				sponge.Squeeze(groupOutputs, offset, Math.Min(StreamBlockLength, zLength - offset));
			}

			for (int j = 0; j < count; ++j)
			{
				TKernel.DecodeZ(groupOutputs.Slice(j * zLength, zLength), y.Slice((done + j) * N, N), TParameters.Gamma1Bits);
			}
		}

		sponge.ZeroMemory();

		if (!message.IsEmpty)
		{
			if (hashSteps > 0)
			{
				guest.Absorb(message.Slice(hashed));
				guest.Pad(KeccakDomainSeparator.Shake);
			}

			guest.Squeeze(hash);
			guest.ZeroMemory();
		}
	}

	// Resets sponge to as many of the streams SHAKE256 streams as one batch takes, leaving room for guests where the kernel has it;
	// stream j absorbs seed ‖ IntegerToBytes(first + j, 2).
	private static void AbsorbSeeds(ref KeccakBatchSponge<KeccakRate136> sponge, ReadOnlySpan<byte> seed, int first, int streams, int guests, Span<byte> inputs)
	{
		Debug.Assert(seed.Length is HashLength);

		sponge.ResetWithGuests(streams, guests);
		int count = sponge.Count;
		Debug.Assert(count <= MaxStreams);
		inputs = inputs.Slice(0, count * StreamInputLength);

		for (int j = 0; j < count; ++j)
		{
			Span<byte> input = inputs.Slice(j * StreamInputLength, StreamInputLength);
			seed.CopyTo(input);
			BinaryPrimitives.WriteUInt16LittleEndian(input.Slice(HashLength), (ushort)(first + j));
		}

		sponge.Absorb(inputs);
		sponge.Pad(KeccakDomainSeparator.Shake);
	}

	// H(first ‖ second ‖ third, destination.Length), with H SHAKE256.
	private static void Shake256(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third, Span<byte> destination)
	{
		KeccakSponge<KeccakRate136> sponge = default;
		sponge.Absorb(first);
		sponge.Absorb(second);
		sponge.Absorb(third);
		sponge.Pad(KeccakDomainSeparator.Shake);
		sponge.Squeeze(destination);
		sponge.ZeroMemory();
	}
}
