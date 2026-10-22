using CryptoBase.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Kems.MLKem;

// ML-KEM (FIPS 203) with Â sampled once and kept transposed. ŝ and t̂ keep the ranges of IMLKemKernel rather than [0, q).
// Encapsulation and decapsulation write to the key only to cache H(ek).
internal struct MLKemKey<TParameters> where TParameters : struct, IMLKemParameters
{
	internal const int PrivateSeedLength = 2 * SymmetricLength;
	internal const int SharedSecretLength = SymmetricLength;

	// The length of d, z, ρ, σ, m, r, H(ek) and K.
	private const int SymmetricLength = 32;

	private const int N = MLKemConstants.N;
	private const int EncodedPolynomialLength = 384;
	private const int Eta2 = 2;

	// Three SHAKE128 blocks rarely fall short of 256 coefficients; SampleRemaining squeezes the rest.
	private const int MatrixBlocks = 3;
	private const int MatrixBlockLength = 168;
	private const int MatrixSqueezeLength = MatrixBlocks * MatrixBlockLength;

	// The k² polynomials of Â^T row by row, t̂, then ŝ if the key holds it.
	private short[]? _polynomials;

	private InlineArray32<byte> _rho;

	// Key generation absorbs only part of ek; the first use of H(ek) finishes it, beside J in decapsulation.
	private InlineArray32<byte> _encapsulationKeyHash;
	private KeccakSponge<KeccakRate136> _partialEncapsulationKeyHash;
	private int _encapsulationKeyHashAbsorbed;
	private bool _hasEncapsulationKeyHash;

	private InlineArray32<byte> _z;
	private InlineArray32<byte> _d;

	internal static int EncapsulationKeyLength => EncodedPolynomialLength * K + SymmetricLength;

	internal static int DecapsulationKeyLength => 2 * EncodedPolynomialLength * K + 3 * SymmetricLength;

	internal static int CiphertextLength => SymmetricLength * (TParameters.Du * K + TParameters.Dv);

	// The longer of the η1 and η2 outputs, so that all 2k + 1 PRF streams share batches.
	private static int EncryptionPrfLength => 64 * Math.Max(TParameters.Eta1, Eta2);

	internal bool HasPrivateSeed { readonly get; private set; }

	internal bool HasDecapsulationKey { readonly get; private set; }

	private static int K => TParameters.K;

	private readonly Span<short> Matrix => _polynomials.AsSpan(0, K * K * N);

	private readonly Span<short> PublicVector => _polynomials.AsSpan(K * K * N, K * N);

	private readonly Span<short> SecretVector => _polynomials.AsSpan((K * K + K) * N, K * N);

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> Rho => _rho;

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> EncapsulationKeyHash => _encapsulationKeyHash;

	// Pairs with the Volatile.Write in CompleteEncapsulationKeyHash.
	private readonly bool HasEncapsulationKeyHash => Volatile.Read(in _hasEncapsulationKeyHash);

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> Z => _z;

	[UnscopedRef]
	private readonly ReadOnlySpan<byte> D => _d;

	[SkipLocalsInit]
	internal void GenerateKey()
	{
		using CryptoBuffer<byte> seed = new(stackalloc byte[PrivateSeedLength]);
		SystemRandom.Fill(seed.Span);
		GenerateKey<MLKemKernelDispatch>(seed.Span);
	}

	internal void ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateSeedLength, nameof(source));
		GenerateKey<MLKemKernelDispatch>(source);
	}

	internal void ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, EncapsulationKeyLength, nameof(source));

		_polynomials = new short[(K * K + K) * N];

		if (!ImportEncapsulationKey<MLKemKernelDispatch>(source))
		{
			Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	// The checks of Sec. 7.3, plus the modulus check on ŝ.
	internal void ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, DecapsulationKeyLength, nameof(source));

		_polynomials = new short[(K * K + 2 * K) * N];

		if (!ImportDecapsulationKey<MLKemKernelDispatch>(source))
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

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateSeedLength, nameof(destination));

		D.CopyTo(destination);
		Z.CopyTo(destination.Slice(SymmetricLength));
		return PrivateSeedLength;
	}

	// dk = ByteEncode_12(ŝ) ‖ ek ‖ H(ek) ‖ z (Algorithm 16, line 3).
	internal int ExportDecapsulationKey(Span<byte> destination)
	{
		if (!HasDecapsulationKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, DecapsulationKeyLength, nameof(destination));

		int secretLength = EncodedPolynomialLength * K;
		int hashOffset = secretLength + EncapsulationKeyLength;
		EncodeVector<MLKemKernelDispatch>(SecretVector, destination);
		EncodeEncapsulationKey<MLKemKernelDispatch>(destination.Slice(secretLength));

		// Not from destination, which the caller may change meanwhile.
		if (!HasEncapsulationKeyHash)
		{
			scoped OverlappedHash none = default;
			CompleteEncapsulationKeyHash<MLKemKernelDispatch>(ref none);
		}

		EncapsulationKeyHash.CopyTo(destination.Slice(hashOffset));
		Z.CopyTo(destination.Slice(hashOffset + SymmetricLength));
		return DecapsulationKeyLength;
	}

	internal readonly int ExportEncapsulationKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EncapsulationKeyLength, nameof(destination));

		EncodeEncapsulationKey<MLKemKernelDispatch>(destination);
		return EncapsulationKeyLength;
	}

	[SkipLocalsInit]
	internal void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfInvalidEncapsulationBuffers(ciphertext, sharedSecret);

		using CryptoBuffer<byte> message = new(stackalloc byte[SymmetricLength]);
		SystemRandom.Fill(message.Span);
		Encapsulate<MLKemKernelDispatch>(message.Span, ciphertext, sharedSecret);
	}

	// ML-KEM.Encaps_internal (Algorithm 17) with a given m, for known-answer tests.
	[SkipLocalsInit]
	internal void Encapsulate(ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(message.Length, SymmetricLength, nameof(message));
		ThrowIfInvalidEncapsulationBuffers(ciphertext, sharedSecret);

		using CryptoBuffer<byte> messageCopy = new(stackalloc byte[SymmetricLength]);
		message.CopyTo(messageCopy.Span);
		Encapsulate<MLKemKernelDispatch>(messageCopy.Span, ciphertext, sharedSecret);
	}

	internal void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
	{
		if (!HasDecapsulationKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		// The ciphertext type check of Sec. 7.3.
		ArgumentOutOfRangeException.ThrowIfNotEqual(ciphertext.Length, CiphertextLength, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		Decapsulate<MLKemKernelDispatch>(ciphertext, sharedSecret);
	}

	internal void Clear()
	{
		_polynomials.AsSpan().ZeroMemory();
		_rho.ZeroMemory();
		_encapsulationKeyHash.ZeroMemory();
		_partialEncapsulationKeyHash.ZeroMemory();
		_encapsulationKeyHashAbsorbed = 0;
		_hasEncapsulationKeyHash = false;
		_z.ZeroMemory();
		_d.ZeroMemory();
		HasPrivateSeed = false;
		HasDecapsulationKey = false;
	}

	private static void ThrowIfInvalidEncapsulationBuffers(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, CiphertextLength, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		if (ciphertext.Slice(0, CiphertextLength).Overlaps(sharedSecret.Slice(0, SharedSecretLength)))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedSecret));
		}
	}

	// ML-KEM.KeyGen_internal (Algorithm 16) with K-PKE.KeyGen (Algorithm 13); seed is d ‖ z.
	[SkipLocalsInit]
	private void GenerateKey<TKernel>(ReadOnlySpan<byte> seed) where TKernel : IMLKemKernel
	{
		int k = K;
		int prfLength = 64 * TParameters.Eta1;
		ReadOnlySpan<byte> d = seed.Slice(0, SymmetricLength);
		_polynomials = new short[(k * k + 2 * k) * N];

		// (ρ, σ) ← G(d ‖ k) (Algorithm 13, line 1).
		using CryptoBuffer<byte> rhoSigma = new(stackalloc byte[2 * SymmetricLength]);
		byte rank = (byte)k;
		G(d, new ReadOnlySpan<byte>(in rank), rhoSigma.Span);
		rhoSigma.Span.Slice(0, SymmetricLength).CopyTo(_rho);

		// H(ek) absorbs ek as each t̂[c] completes, so the PRF streams take the free lanes of the first two columns of
		// Â^T, and H those of the rest.
		using CryptoBuffer<byte> prfOutputs = new(stackalloc byte[2 * k * prfLength]);
		using CryptoBuffer<KeccakSponge<KeccakRate136>> prfSponges = new(stackalloc KeccakSponge<KeccakRate136>[2 * k]);
		scoped PrfGuests prf = new(rhoSigma.Span.Slice(SymmetricLength), prfSponges.Span, prfOutputs.Span, prfLength);
		scoped OverlappedHash none = default;
		Unsafe.SkipInit(out KeccakBatchSponge<KeccakRate168> sponge);
		int firstColumns = Math.Min(k, 2) * k;
		int sampled = 0;

		while (sampled < firstColumns)
		{
			sampled += SampleMatrixGroup<TKernel>(ref sponge, sampled, firstColumns, ref none, ref prf);
		}

		// Its free lanes held PRF state.
		sponge.ZeroMemory();
		prf.Finish();

		Span<short> s = SecretVector;

		for (int i = 0; i < k; ++i)
		{
			Span<short> polynomial = s.Slice(i * N, N);
			TKernel.SampleCbd(prfOutputs.Span.Slice(i * prfLength, prfLength), polynomial, TParameters.Eta1);
			TKernel.Ntt(polynomial);
		}

		Span<byte> encapsulationKey = stackalloc byte[EncapsulationKeyLength];
		Rho.CopyTo(encapsulationKey.Slice(EncodedPolynomialLength * k));
		scoped OverlappedHash hash = new([], encapsulationKey, 0, KeccakDomainSeparator.Sha3);
		using CryptoBuffer<short> error = new(stackalloc short[N]);

		for (int column = 0; column < k;)
		{
			if (sampled < (column + 1) * k)
			{
				sampled += SampleMatrixGroup<TKernel>(ref sponge, sampled, k * k, ref hash, ref prf);
				continue;
			}

			ComputePublicPolynomial<TKernel>(column, prfOutputs.Span.Slice((k + column) * prfLength, prfLength), error.Span, encapsulationKey.Slice(column * EncodedPolynomialLength, EncodedPolynomialLength));
			++column;
			hash.Available = column == k ? encapsulationKey.Length : column * EncodedPolynomialLength;
		}

		hash.Suspend(out _partialEncapsulationKeyHash, out _encapsulationKeyHashAbsorbed);
		d.CopyTo(_d);
		seed.Slice(SymmetricLength).CopyTo(_z);
		HasPrivateSeed = true;
		HasDecapsulationKey = true;
	}

	// t̂[c] (Algorithm 13, lines 17 to 19); row c of Â is column c of Â^T.
	private readonly void ComputePublicPolynomial<TKernel>(int column, ReadOnlySpan<byte> errorSource, Span<short> error, Span<byte> encoded) where TKernel : IMLKemKernel
	{
		int k = K;
		Span<short> polynomial = PublicVector.Slice(column * N, N);
		TKernel.MultiplyAccumulate(Matrix.Slice(column * N), k * N, SecretVector, polynomial, k);
		TKernel.ToMontgomery(polynomial);
		TKernel.SampleCbd(errorSource, error, TParameters.Eta1);
		TKernel.Ntt(error);
		TKernel.Add(polynomial, error, polynomial);
		TKernel.Reduce(polynomial);
		TKernel.Encode12(polynomial, encoded);
	}

	private bool ImportEncapsulationKey<TKernel>(ReadOnlySpan<byte> source) where TKernel : IMLKemKernel
	{
		int vectorLength = EncodedPolynomialLength * K;

		if (!DecodeVector<TKernel>(source.Slice(0, vectorLength), PublicVector))
		{
			return false;
		}

		source.Slice(vectorLength, SymmetricLength).CopyTo(_rho);

		scoped OverlappedHash hash = new([], source, source.Length, KeccakDomainSeparator.Sha3);
		scoped PrfGuests none = default;
		Unsafe.SkipInit(out KeccakBatchSponge<KeccakRate168> sponge);

		for (int first = 0; first < K * K;)
		{
			first += SampleMatrixGroup<TKernel>(ref sponge, first, K * K, ref hash, ref none);
		}

		hash.Finish(_encapsulationKeyHash);
		_hasEncapsulationKeyHash = true;
		return true;
	}

	private bool ImportDecapsulationKey<TKernel>(ReadOnlySpan<byte> source) where TKernel : IMLKemKernel
	{
		int secretLength = EncodedPolynomialLength * K;
		int hashOffset = secretLength + EncapsulationKeyLength;

		if (!ImportEncapsulationKey<TKernel>(source.Slice(secretLength, EncapsulationKeyLength))
			|| !FixedTime.Equals(EncapsulationKeyHash, source.Slice(hashOffset, SymmetricLength))
			|| !DecodeVector<TKernel>(source.Slice(0, secretLength), SecretVector))
		{
			return false;
		}

		source.Slice(hashOffset + SymmetricLength, SymmetricLength).CopyTo(_z);
		HasDecapsulationKey = true;
		return true;
	}

	// ML-KEM.Encaps_internal (Algorithm 17).
	[SkipLocalsInit]
	private void Encapsulate<TKernel>(ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret) where TKernel : IMLKemKernel
	{
		if (!HasEncapsulationKeyHash)
		{
			scoped OverlappedHash none = default;
			CompleteEncapsulationKeyHash<TKernel>(ref none);
		}

		// (K, r) ← G(m ‖ H(ek)) (line 1), c ← K-PKE.Encrypt(ek, m, r) (line 2).
		using CryptoBuffer<byte> keyAndRandomness = new(stackalloc byte[2 * SymmetricLength]);
		G(message, EncapsulationKeyHash, keyAndRandomness.Span);
		using CryptoBuffer<byte> prfOutputs = new(stackalloc byte[(2 * K + 1) * EncryptionPrfLength]);
		Prf(keyAndRandomness.Span.Slice(SymmetricLength), 0, 2 * K + 1, EncryptionPrfLength, prfOutputs.Span);
		Encrypt<TKernel>(message, prfOutputs.Span, ciphertext);
		keyAndRandomness.Span.Slice(0, SharedSecretLength).CopyTo(sharedSecret);
	}

	// ML-KEM.Decaps_internal (Algorithm 18). The ciphertext is read in full before the shared secret is written, so the two may overlap.
	[SkipLocalsInit]
	private void Decapsulate<TKernel>(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret) where TKernel : IMLKemKernel
	{
		using CryptoBuffer<byte> secrets = new(stackalloc byte[4 * SymmetricLength]);
		Span<byte> message = secrets.Span.Slice(0, SymmetricLength);
		Span<byte> keyAndRandomness = secrets.Span.Slice(SymmetricLength, 2 * SymmetricLength);
		Span<byte> rejectionKey = secrets.Span.Slice(3 * SymmetricLength, SymmetricLength);

		// m' ← K-PKE.Decrypt(dk_PKE, c) (line 5).
		Decrypt<TKernel>(ciphertext, message);

		// K̄ ← J(z ‖ c) (line 7) runs beside H(ek), G and the PRF. The schedule does not depend on the ciphertext.
		OverlappedHash j = new(Z, ciphertext, ciphertext.Length, KeccakDomainSeparator.Shake);

		if (!HasEncapsulationKeyHash)
		{
			CompleteEncapsulationKeyHash<TKernel>(ref j);
		}

		KeccakSponge<KeccakRate72> g = default;
		g.Absorb(message);
		g.AbsorbBlock(EncapsulationKeyHash, KeccakDomainSeparator.Sha3);

		if (j.CanStep)
		{
			KeccakP1600Batch.Permute(ref g, ref j.Step());
		}
		else
		{
			g.Permute();
		}

		g.Squeeze(keyAndRandomness);
		g.ZeroMemory();

		using CryptoBuffer<byte> prfOutputs = new(stackalloc byte[(2 * K + 1) * EncryptionPrfLength]);
		Prf(keyAndRandomness.Slice(SymmetricLength), 0, 2 * K + 1, EncryptionPrfLength, prfOutputs.Span, ref j);
		j.Finish(rejectionKey);
		using CryptoBuffer<byte> reencrypted = new(stackalloc byte[CiphertextLength]);
		Encrypt<TKernel>(message, prfOutputs.Span, reencrypted.Span);

		// K' if c = c', else K̄ (lines 9 to 11), chosen by a mask rather than a branch.
		ulong mask = 0UL - Unsafe.BitCast<bool, byte>(FixedTime.Equals(ciphertext, reencrypted.Span));
		ref byte accepted = ref MemoryMarshal.GetReference(keyAndRandomness);
		ref byte rejected = ref MemoryMarshal.GetReference(rejectionKey);
		ref byte destination = ref MemoryMarshal.GetReference(sharedSecret);

		for (nint offset = 0; offset < SharedSecretLength; offset += sizeof(ulong))
		{
			ulong selected = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref accepted, offset)) & mask | Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rejected, offset)) & ~mask;
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, offset), selected);
		}
	}

	// Concurrent callers write the same bytes, so no lock is needed; the flag is set last.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void CompleteEncapsulationKeyHash<TKernel>(scoped ref OverlappedHash beside) where TKernel : IMLKemKernel
	{
		Span<byte> encapsulationKey = stackalloc byte[EncapsulationKeyLength];
		EncodeEncapsulationKey<TKernel>(encapsulationKey);
		scoped OverlappedHash hash = new(in _partialEncapsulationKeyHash, _encapsulationKeyHashAbsorbed, encapsulationKey);

		while (hash.CanStep && beside.CanStep)
		{
			KeccakP1600Batch.Permute(ref hash.Step(), ref beside.Step());
		}

		Span<byte> value = stackalloc byte[SymmetricLength];
		hash.Finish(value);
		value.CopyTo(_encapsulationKeyHash);
		Volatile.Write(ref _hasEncapsulationKeyHash, true);
	}

	// K-PKE.Encrypt (Algorithm 14) given PRF(r, 0) to PRF(r, 2k), so that decapsulation can run J beside the PRF.
	[SkipLocalsInit]
	private readonly void Encrypt<TKernel>(ReadOnlySpan<byte> message, ReadOnlySpan<byte> prfOutputs, Span<byte> ciphertext) where TKernel : IMLKemKernel
	{
		int k = K;
		int du = TParameters.Du;
		int dv = TParameters.Dv;
		int prfLength = EncryptionPrfLength;

		using CryptoBuffer<short> polynomials = new(stackalloc short[(k + 2) * N]);
		Span<short> y = polynomials.Span.Slice(0, k * N);
		Span<short> sum = polynomials.Span.Slice(k * N, N);
		Span<short> error = polynomials.Span.Slice((k + 1) * N, N);

		for (int i = 0; i < k; ++i)
		{
			Span<short> polynomial = y.Slice(i * N, N);
			TKernel.SampleCbd(prfOutputs.Slice(i * prfLength, prfLength), polynomial, TParameters.Eta1);
			TKernel.Ntt(polynomial);
		}

		// u ← NTT⁻¹(Â^T ∘ ŷ) + e1, c1 ← ByteEncode_du(Compress_du(u)).
		for (int i = 0; i < k; ++i)
		{
			TKernel.MultiplyAccumulate(Matrix.Slice(i * k * N), N, y, sum, k);
			TKernel.InverseNtt(sum);
			TKernel.SampleCbd(prfOutputs.Slice((k + i) * prfLength, prfLength), error, Eta2);
			TKernel.Add(sum, error, sum);
			TKernel.Reduce(sum);
			TKernel.Compress(sum, ciphertext.Slice(i * SymmetricLength * du, SymmetricLength * du), du);
		}

		// v ← NTT⁻¹(t̂^T ∘ ŷ) + e2 + μ with μ = Decompress_1(ByteDecode_1(m)), c2 ← ByteEncode_dv(Compress_dv(v)).
		TKernel.MultiplyAccumulate(PublicVector, N, y, sum, k);
		TKernel.InverseNtt(sum);
		TKernel.SampleCbd(prfOutputs.Slice(2 * k * prfLength, prfLength), error, Eta2);
		TKernel.Add(sum, error, sum);
		TKernel.Decompress(message, error, 1);
		TKernel.Add(sum, error, sum);
		TKernel.Reduce(sum);
		TKernel.Compress(sum, ciphertext.Slice(k * SymmetricLength * du, SymmetricLength * dv), dv);
	}

	// K-PKE.Decrypt (Algorithm 15).
	[SkipLocalsInit]
	private readonly void Decrypt<TKernel>(ReadOnlySpan<byte> ciphertext, Span<byte> message) where TKernel : IMLKemKernel
	{
		int k = K;
		int du = TParameters.Du;
		int dv = TParameters.Dv;
		using CryptoBuffer<short> polynomials = new(stackalloc short[(k + 1) * N]);
		Span<short> u = polynomials.Span.Slice(0, k * N);
		Span<short> w = polynomials.Span.Slice(k * N, N);

		// û ← NTT(Decompress_du(ByteDecode_du(c1))).
		for (int i = 0; i < k; ++i)
		{
			Span<short> polynomial = u.Slice(i * N, N);
			TKernel.Decompress(ciphertext.Slice(i * SymmetricLength * du, SymmetricLength * du), polynomial, du);
			TKernel.Ntt(polynomial);
		}

		// w ← v' − NTT⁻¹(ŝ^T ∘ û); v' reuses the first polynomial of û.
		TKernel.MultiplyAccumulate(SecretVector, N, u, w, k);
		TKernel.InverseNtt(w);
		Span<short> v = u.Slice(0, N);
		TKernel.Decompress(ciphertext.Slice(k * SymmetricLength * du, SymmetricLength * dv), v, dv);
		TKernel.Subtract(v, w, w);
		TKernel.Reduce(w);

		// m ← ByteEncode_1(Compress_1(w)).
		TKernel.Compress(w, message, 1);
	}

	// Samples the entries of Â^T from first on that one batch takes, and returns how many. Â[j, i] = SampleNTT(ρ ‖ i ‖ j) is entry
	// j · k + i, so the columns complete in order. Waiting PRF streams, or else hash, take the free lanes.
	[SkipLocalsInit]
	private readonly int SampleMatrixGroup<TKernel>(scoped ref KeccakBatchSponge<KeccakRate168> sponge, int first, int end, scoped ref OverlappedHash hash, scoped ref PrfGuests prf) where TKernel : IMLKemKernel
	{
		const int MaxStreams = 8;
		int k = K;
		int streams = end - first;
		int guests = 0;

		if (prf.Waiting > 0)
		{
			guests = prf.Waiting;
		}
		else if (hash.CanFill(MatrixBlocks))
		{
			streams = Math.Min(streams, Math.Max(KeccakP1600Batch.MaxLanes - 1, 1));
			guests = 1;
		}

		// The i ‖ j after ρ.
		Span<ushort> suffixes = stackalloc ushort[MaxStreams];
		suffixes = suffixes.Slice(0, Math.Min(streams, MaxStreams));

		for (int j = 0; j < suffixes.Length; ++j)
		{
			int entry = first + j;
			suffixes[j] = (ushort)(entry % k | entry / k << 8);
		}

		sponge.ResetWithGuests(streams, guests, Rho, suffixes, sizeof(ushort), KeccakDomainSeparator.Shake);
		int count = sponge.Count;
		Debug.Assert(count <= MaxStreams);
		Span<byte> outputs = stackalloc byte[MaxStreams * MatrixSqueezeLength];
		outputs = outputs.Slice(0, count * MatrixSqueezeLength);

		for (int block = 0; block < MatrixBlocks; ++block)
		{
			if (prf.Waiting > 0 && sponge.FreeLanes > 0)
			{
				prf.PermuteWith(ref sponge);
			}
			else if (hash.CanStep && sponge.FreeLanes > 0)
			{
				hash.PermuteWith(ref sponge);
			}

			sponge.Squeeze(outputs, block * MatrixBlockLength, MatrixBlockLength);
		}

		for (int j = 0; j < count; ++j)
		{
			int entry = first + j;
			Span<short> polynomial = Matrix.Slice((entry % k * k + entry / k) * N, N);
			int sampled = TKernel.RejectSample(outputs.Slice(j * MatrixSqueezeLength, MatrixSqueezeLength), polynomial);

			if (sampled < N)
			{
				SampleRemaining<TKernel>(sponge.ExtractLane(j), polynomial, sampled);
			}
		}

		return count;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void SampleRemaining<TKernel>(KeccakSponge<KeccakRate168> sponge, Span<short> polynomial, int sampled) where TKernel : IMLKemKernel
	{
		Span<byte> block = stackalloc byte[KeccakRate168.RateInBytes];

		while (sampled < N)
		{
			sponge.Squeeze(block);
			sampled += TKernel.RejectSample(block, polynomial.Slice(sampled));
		}
	}

	// PRF_η(s, b) = SHAKE256(s ‖ b) (Sec. 4.1) for b from first on.
	private static void Prf(ReadOnlySpan<byte> seed, int first, int streams, int length, Span<byte> outputs)
	{
		scoped OverlappedHash none = default;
		Prf(seed, first, streams, length, outputs, ref none);
	}

	// hash gets a lane only if it can fill every permutation of the batch, since on narrow kernels the lane can cost a batch.
	[SkipLocalsInit]
	private static void Prf(ReadOnlySpan<byte> seed, int first, int streams, int length, Span<byte> outputs, scoped ref OverlappedHash hash)
	{
		const int MaxStreams = 8;
		Span<ushort> nonceBuffer = stackalloc ushort[MaxStreams];
		Unsafe.SkipInit(out KeccakBatchSponge<KeccakRate136> sponge);
		int blocks = (length + KeccakRate136.RateInBytes - 1) / KeccakRate136.RateInBytes;

		for (int done = 0; done < streams; done += sponge.Count)
		{
			int group = streams - done;
			int guests = 0;

			if (hash.CanFill(blocks))
			{
				group = Math.Min(group, Math.Max(KeccakP1600Batch.MaxLanes - 1, 1));
				guests = 1;
			}

			Span<ushort> nonces = nonceBuffer.Slice(0, Math.Min(group, MaxStreams));

			for (int j = 0; j < nonces.Length; ++j)
			{
				nonces[j] = (byte)(first + done + j);
			}

			sponge.ResetWithGuests(group, guests, seed, nonces, sizeof(byte), KeccakDomainSeparator.Shake);
			int count = sponge.Count;
			Debug.Assert(count <= MaxStreams);
			Span<byte> groupOutputs = outputs.Slice(done * length, count * length);

			for (int offset = 0; offset < length; offset += KeccakRate136.RateInBytes)
			{
				if (hash.CanStep && sponge.FreeLanes > 0)
				{
					hash.PermuteWith(ref sponge);
				}

				sponge.Squeeze(groupOutputs, offset, Math.Min(KeccakRate136.RateInBytes, length - offset));
			}
		}

		sponge.ZeroMemory();
	}

	// G(a ‖ b) = SHA3-512(a ‖ b) (Sec. 4.1), into 64 bytes.
	private static void G(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> destination)
	{
		KeccakSponge<KeccakRate72> sponge = default;
		sponge.Absorb(first);
		sponge.Absorb(second);
		sponge.Pad(KeccakDomainSeparator.Sha3);
		sponge.Squeeze(destination.Slice(0, 2 * SymmetricLength));
		sponge.ZeroMemory();
	}

	// ek = ByteEncode_12(t̂) ‖ ρ.
	private readonly void EncodeEncapsulationKey<TKernel>(Span<byte> destination) where TKernel : IMLKemKernel
	{
		EncodeVector<TKernel>(PublicVector, destination);
		Rho.CopyTo(destination.Slice(EncodedPolynomialLength * K));
	}

	private static void EncodeVector<TKernel>(ReadOnlySpan<short> vector, Span<byte> destination) where TKernel : IMLKemKernel
	{
		for (int i = 0; i < K; ++i)
		{
			TKernel.Encode12(vector.Slice(i * N, N), destination.Slice(i * EncodedPolynomialLength, EncodedPolynomialLength));
		}
	}

	// Must not stop at the first invalid polynomial.
	private static bool DecodeVector<TKernel>(ReadOnlySpan<byte> source, Span<short> vector) where TKernel : IMLKemKernel
	{
		bool valid = true;

		for (int i = 0; i < K; ++i)
		{
			valid &= TKernel.Decode12(source.Slice(i * EncodedPolynomialLength, EncodedPolynomialLength), vector.Slice(i * N, N));
		}

		return valid;
	}

	// The PRF streams of key generation (Algorithm 13, lines 8 to 15), run in free lanes of the matrix sampling.
	// A default instance has no streams.
	private ref struct PrfGuests
	{
		private readonly ReadOnlySpan<byte> _seed;
		private readonly Span<KeccakSponge<KeccakRate136>> _sponges;
		private readonly Span<byte> _outputs;
		private readonly int _length;

		// Streams in [_first, _end) are under way; those before _first are done.
		private int _first;
		private int _end;
		private int _squeezed;

		internal PrfGuests(ReadOnlySpan<byte> seed, Span<KeccakSponge<KeccakRate136>> sponges, Span<byte> outputs, int length)
		{
			_seed = seed;
			_sponges = sponges;
			_outputs = outputs;
			_length = length;
		}

		internal readonly int Waiting => _sponges.Length - _first;

		internal void PermuteWith(ref KeccakBatchSponge<KeccakRate168> host)
		{
			if (_end == _first)
			{
				_end = _first + Math.Min(host.FreeLanes, _sponges.Length - _first);
				_squeezed = 0;

				for (int b = _first; b < _end; ++b)
				{
					ref KeccakSponge<KeccakRate136> sponge = ref _sponges[b];
					byte nonce = (byte)b;
					sponge = default;
					sponge.Absorb(_seed);
					sponge.AbsorbBlock(new ReadOnlySpan<byte>(in nonce), KeccakDomainSeparator.Shake);
				}
			}

			host.Permute(_sponges.Slice(_first, _end - _first));
			int length = Math.Min(KeccakRate136.RateInBytes, _length - _squeezed);

			for (int b = _first; b < _end; ++b)
			{
				_sponges[b].Squeeze(_outputs.Slice(b * _length + _squeezed, length));
			}

			_squeezed += length;

			if (_squeezed == _length)
			{
				_first = _end;
			}
		}

		internal void Finish()
		{
			for (int b = _first; b < _end; ++b)
			{
				_sponges[b].Squeeze(_outputs.Slice(b * _length + _squeezed, _length - _squeezed));
			}

			if (_end < _sponges.Length)
			{
				Prf(_seed, _end, _sponges.Length - _end, _length, _outputs.Slice(_end * _length));
			}

			_first = _sponges.Length;
			_end = _sponges.Length;
		}
	}

	// J(z ‖ c) or H(ek), permuted a block at a time beside other permutations. Only the first Available bytes of
	// the message need be known. A default instance hashes nothing.
	private ref struct OverlappedHash
	{
		private readonly ReadOnlySpan<byte> _message;
		private readonly byte _domainSeparator;
		private KeccakSponge<KeccakRate136> _sponge;
		private int _absorbed;

		// The prefix until the first step, then 0.
		private int _inBlock;

		internal OverlappedHash(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> message, int available, byte domainSeparator)
		{
			_message = message;
			_domainSeparator = domainSeparator;
			_sponge = default;
			_sponge.Absorb(prefix);
			_inBlock = prefix.Length;
			Available = available;
		}

		// Resumes H(ek) from Suspend.
		internal OverlappedHash(in KeccakSponge<KeccakRate136> sponge, int absorbed, ReadOnlySpan<byte> message)
		{
			_message = message;
			_domainSeparator = KeccakDomainSeparator.Sha3;
			_sponge = sponge;
			_absorbed = absorbed;
			Available = message.Length;
		}

		internal int Available { readonly get; set; }

		// Until the message is all known, a step needs a whole block of it.
		internal readonly bool CanStep => _domainSeparator is not 0 && !_sponge.IsSqueezing && (Available == _message.Length || Available - _absorbed >= KeccakRate136.RateInBytes);

		internal readonly bool CanFill(int permutations)
		{
			if (_domainSeparator is 0 || _sponge.IsSqueezing)
			{
				return false;
			}

			int steps = (_inBlock + Available - _absorbed) / KeccakRate136.RateInBytes;

			// The padded last block, even after a whole block.
			if (Available == _message.Length)
			{
				++steps;
			}

			return steps >= permutations;
		}

		// The caller permutes, so that two hashes can share one.
		[UnscopedRef]
		internal ref KeccakSponge<KeccakRate136> Step()
		{
			AbsorbBlock();
			return ref _sponge;
		}

		internal void PermuteWith<TRate>(ref KeccakBatchSponge<TRate> host) where TRate : IKeccakRate
		{
			AbsorbBlock();
			host.Permute(new Span<KeccakSponge<KeccakRate136>>(ref _sponge));
		}

		internal readonly void Suspend(out KeccakSponge<KeccakRate136> sponge, out int absorbed)
		{
			Debug.Assert(_inBlock is 0 && !_sponge.AwaitsPermutation);

			sponge = _sponge;
			absorbed = _absorbed;
		}

		// Erases the state, which for J holds z.
		internal void Finish(Span<byte> destination)
		{
			Debug.Assert(_domainSeparator is not 0 && Available == _message.Length);

			if (!_sponge.IsSqueezing)
			{
				_sponge.Absorb(_message.Slice(_absorbed));
				_sponge.Pad(_domainSeparator);
			}

			_sponge.Squeeze(destination.Slice(0, SymmetricLength));
			_sponge.ZeroMemory();
		}

		private void AbsorbBlock()
		{
			Debug.Assert(CanStep);

			_absorbed += _sponge.AbsorbBlock(_message.Slice(_absorbed, Available - _absorbed), _domainSeparator);
			_inBlock = 0;
		}
	}
}
