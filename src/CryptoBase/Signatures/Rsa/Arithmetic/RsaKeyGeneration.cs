namespace CryptoBase.Signatures.Rsa.Arithmetic;

// An RSA key pair of FIPS 186-5, Appendix A.1: the primes of Appendix A.1.3, d = e⁻¹ mod λ(n) with 2^(nlen/2) < d < λ(n) (Appendix A.1.1, criterion 3), and the CRT values of RFC 8017, Sec. 3.2. Nothing depends on the secrets in time or addresses but the rejection of a pair whose d is too small, after which new primes are drawn.
// With e small and public, each inverse modulo an even m comes from k = −m⁻¹ mod e: 1 + k·m is then a multiple of e, and (1 + k·m)/e, below m, is e⁻¹ mod m.
internal static class RsaKeyGeneration
{
	// n has ⌈nlen/64⌉ limbs and d as many; p, q, dP, dQ and qInv have ⌈nlen/128⌉.
	internal static void Generate(int nlen, ulong e, Span<ulong> n, Span<ulong> p, Span<ulong> q, Span<ulong> d, Span<ulong> dP, Span<ulong> dQ, Span<ulong> qInv)
	{
		int limbs = p.Length;

		Debug.Assert(n.Length == (nlen + 63) / 64 && d.Length == n.Length && limbs == (nlen / 2 + 63) / 64);
		Debug.Assert(q.Length == limbs && dP.Length == limbs && dQ.Length == limbs && qInv.Length == limbs);

		do
		{
			ProbablePrime.Generate(nlen, e, p, q);
		}
		while (!TryPrivateExponent(nlen, e, p, q, d));

		CrtExponent(e, p, dP);
		CrtExponent(e, q, dQ);
		Coefficient(p, q, qInv);

		int productLength = 2 * limbs;
		using CryptoBuffer<ulong> product = CryptoBuffer<ulong>.ShouldUsePool(productLength) ? new CryptoBuffer<ulong>(productLength) : new CryptoBuffer<ulong>(stackalloc ulong[productLength]);
		Limbs.Multiply(p, q, product.Span);
		product.Span.Slice(0, n.Length).CopyTo(n);
	}

	// d = e⁻¹ mod λ(n), λ(n) = lcm(p − 1, q − 1) = (p − 1)·((q − 1)/gcd(p − 1, q − 1)); false if d ≤ 2^(nlen/2).
	private static bool TryPrivateExponent(int nlen, ulong e, ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> q, Span<ulong> d)
	{
		int limbs = p.Length;
		int bufferLength = 10 * limbs + 2;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> pMinusOne = buffer.Span.Slice(0, limbs);
		Span<ulong> qMinusOne = buffer.Span.Slice(limbs, limbs);
		Span<ulong> gcd = buffer.Span.Slice(2 * limbs, limbs);
		Span<ulong> quotient = buffer.Span.Slice(3 * limbs, limbs);
		Span<ulong> remainder = buffer.Span.Slice(4 * limbs, limbs);
		Span<ulong> scratch = buffer.Span.Slice(5 * limbs, 2 * limbs);
		Span<ulong> lambda = buffer.Span.Slice(7 * limbs, 2 * limbs + 1);
		Span<ulong> bound = buffer.Span.Slice(9 * limbs + 1, limbs + 1);
		p.CopyTo(pMinusOne);
		q.CopyTo(qMinusOne);
		_ = Limbs.SubtractSmall(pMinusOne, 1);
		_ = Limbs.SubtractSmall(qMinusOne, 1);
		int shift = Limbs.Gcd(pMinusOne, qMinusOne, gcd, scratch);
		Limbs.Divide(qMinusOne, gcd, quotient, remainder, scratch);
		Limbs.ShiftRight(quotient, shift);
		Limbs.Multiply(pMinusOne, quotient, lambda.Slice(0, 2 * limbs));
		lambda[^1] = 0;
		InverseOfE(e, lambda);

		// 2^(nlen/2) < d, where λ(n), and so d, has at most nlen bits.
		int half = nlen / 2;
		bound.Clear();
		bound[half / 64] = 1UL << half % 64;
		ulong large = Limbs.LessThan(bound, lambda);
		lambda.Slice(0, d.Length).CopyTo(d);
		return large is not 0;
	}

	// dP = e⁻¹ mod (p − 1).
	private static void CrtExponent(ulong e, ReadOnlySpan<ulong> prime, Span<ulong> exponent)
	{
		int limbs = prime.Length;
		int bufferLength = limbs + 1;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> value = buffer.Span;
		value[^1] = 0;
		prime.CopyTo(value);
		_ = Limbs.SubtractSmall(value, 1);
		InverseOfE(e, value);
		value.Slice(0, limbs).CopyTo(exponent);
	}

	// value = e⁻¹ mod value, for an even value with a zero top limb to spare, coprime to e.
	private static void InverseOfE(ulong e, Span<ulong> value)
	{
		Debug.Assert(value[^1] is 0);

		ulong remainder = SmallModulus.Remainder(value, e);
		// k = −value⁻¹ mod e, which is not zero.
		ulong k = e - SmallModulus.Inverse(remainder, e);
		value[^1] = Limbs.MultiplySmall(value.Slice(0, value.Length - 1), k, 1);
		SmallModulus.DivideExact(value, e);
	}

	// qInv = q⁻¹ mod p, for p and q of nlen/2 bits with their top two bits set, so that q < 2p.
	private static void Coefficient(ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> q, Span<ulong> qInv)
	{
		int limbs = p.Length;
		int bufferLength = 2 * limbs;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> reduced = buffer.Span.Slice(0, limbs);
		Span<ulong> difference = buffer.Span.Slice(limbs, limbs);
		ulong borrow = Limbs.Subtract(q, p, difference);
		Limbs.Select(0 - borrow, q, difference, reduced);
		ModularInverse.Invert(reduced, [1], p, qInv);
	}
}
