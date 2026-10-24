namespace CryptoBase.Signatures.MLDsa;

// The polynomial operations of ML-DSA on 256 int32 coefficients in the order of FIPS 204, whatever a kernel does in registers. Unless stated otherwise, a coefficient need only be congruent modulo q and lie in the range that In (from the caller) or Out (from the kernel) gives. Operations on secret data take time independent of the values, except that the rejection samplers stop when the polynomial is full.
internal interface IMLDsaKernel
{
	static abstract bool IsSupported { get; }

	// NTT (Algorithm 41) in place. In: |f| < q. Out: |f| < 9q.
	static abstract void Ntt(Span<int> f);

	// NTT⁻¹ (Algorithm 42) in place, times R = 2^32, which undoes the R⁻¹ of MultiplyAccumulate. In: |f| < q. Out: |f| < q.
	static abstract void InverseNtt(Span<int> f);

	// destination = R⁻¹ · Σ a_j ∘ b_j for j < count, a_j at a[j · 256] and b_j at b[j · 256], with ∘ the coefficient-wise product of AddNTT and MultiplyNTT (Algorithms 44 and 45). In: |a| < q, |b| < 9q, 1 ≤ count ≤ 8. Out: |destination| < q. destination overlaps neither a nor b.
	static abstract void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count);

	// In: |f| < 2^31 − 2^22. Out: |f| ≤ 6283008; f is the centered representative wherever that is below 2097409 in magnitude.
	static abstract void Reduce(Span<int> f);

	// destination = left + right without reduction; the caller keeps the sums within int32. destination may be left or right.
	static abstract void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination);

	// Whether some |f_i| ≥ bound, checking every coefficient. In: f from Reduce, or the exact values; bound ≤ 2097409.
	static abstract bool ExceedsBound(ReadOnlySpan<int> f, int bound);

	// destination = Reduce(left + right), and ExceedsBound of it, in one pass. In: the sums within the input of Reduce. destination may be left or right.
	static abstract bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound);

	// destination = Reduce(left − right), and ExceedsBound of it, in one pass.
	// In: the differences within the input of Reduce. destination may be left or right.
	static abstract bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound);

	// Reduce in place, and ExceedsBound of the result, in one pass.
	static abstract bool ReduceExceedsBound(Span<int> f, int bound);

	// Power2Round (Algorithm 35) of t mod q. In: |t| < 2^31 − 2^22. Out: high in [0, 2^10), low in (−2^12, 2^12], the exact values.
	static abstract void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low);

	// Decompose (Algorithm 36) of r mod q, as HighBits and LowBits (Algorithms 37 and 38). In: |r| < q. Out: high in [0, (q − 1) / (2γ2)), low in [−γ2, γ2], the exact values.
	static abstract void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2);

	// The hint of MakeHint (Algorithm 39) for r = high · 2γ2 + low and z with r + z having the HighBits high, from the low bits alone; returns the number of ones. In: high from Decompose; low is any int32, and the hint is that of Algorithm 39 where |low| < 2γ2. Out: hint in {0, 1}. hint may be low.
	static abstract int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2);

	// UseHint (Algorithm 40) of r mod q. In: |r| < q, hint in {0, 1}. Out: the exact values, in [0, (q − 1) / (2γ2)). destination may be r.
	static abstract void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2);

	// The loop of RejNTTPoly (Algorithm 30, lines 4 to 11), until destination is full or source runs out; returns how many it wrote. source is public and a multiple of three bytes long. Out: the exact values, in [0, q); nothing is written past the returned count.
	static abstract int RejectSample(ReadOnlySpan<byte> source, Span<int> destination);

	// The loop of RejBoundedPoly (Algorithm 31, lines 4 to 15) for η = eta in {2, 4}, until destination is full or source runs out; returns how many it wrote. Out: the exact values, in [−η, η]; past the returned count, at most eight slots of destination may be written, with values that are not samples.
	static abstract int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta);

	// SimpleBitPack(t1, 2^10 − 1) (Algorithm 16) into 320 bytes. In: [0, 2^10).
	static abstract void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination);

	// SimpleBitUnpack(·, 2^10 − 1) (Algorithm 18) of 320 bytes, times 2^d. Out: the exact values, in [0, q).
	static abstract void DecodeT1(ReadOnlySpan<byte> source, Span<int> f);

	// BitPack(t0, 2^12 − 1, 2^12) (Algorithm 17) into 416 bytes. In: (−2^12, 2^12].
	static abstract void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination);

	// BitPack(s, η, η) into 32 · bitlen(2η) bytes for η = eta in {2, 4}. In: [−η, η].
	static abstract void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta);

	// BitUnpack(·, η, η) (Algorithm 19) of 32 · bitlen(2η) bytes; returns whether every value is in [−η, η], the range that the encoding of a valid key holds. Out: η − v for each packed v, whether valid or not.
	static abstract bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta);

	// BitPack(z, γ1 − 1, γ1) into 32 · (1 + log2 γ1) bytes for γ1 = 2^gamma1Bits. In: (−γ1, γ1].
	static abstract void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits);

	// BitUnpack(·, γ1 − 1, γ1) of 32 · (1 + log2 γ1) bytes for γ1 = 2^gamma1Bits. Out: the exact values, in (−γ1, γ1].
	static abstract void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits);

	// SimpleBitPack(w1, (q − 1) / (2γ2) − 1), the part of w1Encode (Algorithm 28) for one polynomial, into 32 · bitlen((q − 1) / (2γ2) − 1) bytes. In: [0, (q − 1) / (2γ2)).
	static abstract void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2);
}
