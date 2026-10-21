namespace CryptoBase.Kems.MLKem;

// The polynomial operations of ML-KEM on 256 int16 coefficients in the order of FIPS 203, whatever a kernel does in registers.
// Unless stated otherwise, a coefficient need only be congruent modulo q and lie in the range that In (from the caller) or Out (from
// the kernel) gives. Operations on secret data take time independent of the values.
internal interface IMLKemKernel
{
	static abstract bool IsSupported { get; }

	// NTT (Algorithm 9) in place. In: |f| < q. Out: |f| < q.
	static abstract void Ntt(Span<short> f);

	// NTT⁻¹ (Algorithm 10) in place, times R = 2^16, which undoes the R⁻¹ of MultiplyAccumulate. In: |f| < q. Out: |f| < q.
	static abstract void InverseNtt(Span<short> f);

	// destination = R⁻¹ · Σ a_j × b_j for j < count, a_j at a[j · aStride] and b_j at b[j · 256], × being MultiplyNTTs (Algorithm 11).
	// In: |a|, |b| < q, 1 ≤ count ≤ 4. Out: |destination| < q. destination overlaps neither a nor b.
	static abstract void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count);

	// In: any. Out: |f| < q.
	static abstract void Reduce(Span<short> f);

	// f · R. In: any. Out: |f| < q.
	static abstract void ToMontgomery(Span<short> f);

	// destination = left + right without reduction; the caller keeps the sums within int16. destination may be left or right.
	static abstract void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination);

	// destination = left − right without reduction; the caller keeps the differences within int16. destination may be left or right.
	static abstract void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination);

	// ByteEncode_12 (Algorithm 5) of f mod q into 384 bytes. In: |f| < q.
	static abstract void Encode12(ReadOnlySpan<short> f, Span<byte> destination);

	// ByteDecode_12 (Algorithm 6) of 384 bytes without the reduction modulo q. Returns whether all the values are below q, the
	// modulus check of Sec. 7.2.
	static abstract bool Decode12(ReadOnlySpan<byte> source, Span<short> f);

	// ByteEncode_d(Compress_d(f mod q)) (Sec. 4.2.1, Algorithm 5) into 32 · d bytes, for d = bits in {1, 4, 5, 10, 11}. In: |f| < q.
	static abstract void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits);

	// Decompress_d(ByteDecode_d(source)) (Sec. 4.2.1, Algorithm 6) from 32 · d bytes, for d = bits in {1, 4, 5, 10, 11}.
	// Out: |f| < q.
	static abstract void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits);

	// The loop of SampleNTT (Algorithm 7, lines 4 to 13), until destination is full or source runs out; returns how many it wrote.
	// source is public and a multiple of three bytes long. Out: the exact values, in [0, q); nothing is written past the returned count.
	static abstract int RejectSample(ReadOnlySpan<byte> source, Span<short> destination);

	// SamplePolyCBD_η (Algorithm 8) from 64 · η bytes, for η = eta in {2, 3}. Out: the exact values, in [−η, η].
	static abstract void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta);
}
