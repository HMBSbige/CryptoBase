namespace CryptoBase.EllipticCurves.SM9;

// The heavy operations of SM9 on the shared types, whatever a kernel uses inside: elements of SM9Fp12, points of SM9Point and SM9AffinePoint with reduced coordinates in Montgomery form, SM9PrecomputedLine lines and plain scalars below N. Points of G1 and G2 passed in are not the point at infinity, which affine points cannot hold. Every member whose name does not end in VariableTime may take secrets: neither its time nor the addresses it reads may depend on its inputs, and it erases the buffers it owns. The VariableTime members take public inputs and may branch on them.
internal interface ISM9Kernel
{
	static abstract bool IsSupported { get; }

	// The Miller loop of SM9MillerLoop for P of G1 and Q of G2, which the final exponentiation maps to e(P, Q). A kernel may give another value with the same image, as one that leaves out other factors of proper subfields.
	static abstract void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result);

	// As above for the P whose factors α = 1/yP and β = xP/yP SM9MillerLoop.FactorsVariableTime gives, with the SM9MillerLoop.LineCount lines that SM9MillerLoop.Precompute gives for Q.
	static abstract void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result);

	// The product of the above for the factors of P with the lines of Q and for those of P′ with the lines of Q′, which the final exponentiation maps to e(P, Q)·e(P′, Q′).
	static abstract void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result);

	// value^((p¹² − 1)/N) for value ≠ 0.
	static abstract void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result);

	// value^k for value in GT.
	static abstract void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result);

	// The table and inverse of SM9GTPower.BuildFixedTable for value in GT, which may be secret, as values; the representatives may differ.
	static abstract void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse);

	// value^k for the table and inverse that SM9GTPower.BuildFixedTable gives for value in GT.
	static abstract void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result);

	// The entries of SM9BaseTable for G of G1 or G2 and the width, window after window. G may be secret, and then so are the entries.
	static abstract void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries);

	static abstract void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries);

	// SM9Curve.ToAffine for points over Fp2, which may be secret; SM9MillerLoop.Precompute divides its lines by it.
	static abstract void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime);

	// k·G for the table of a point G of G1, which may be secret, as a key's is. The projective form of the result depends on k and not only on the product.
	static abstract void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

	// a·G + b·H for the tables of G and H of G1, with a result as above.
	static abstract void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result);

	// k·P for P of G1, with a result as above.
	static abstract void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

	// k·P for a public P of G1 and a public k, with a result as above.
	static abstract void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

	// k·P1 + addend for an addend of G1, which may be the point at infinity.
	static abstract void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result);

	// k·P2, with a result as above.
	static abstract void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result);

	// k·P2 + addend for an addend of G2, which may be the point at infinity.
	static abstract void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result);

	// [a]Q for the scalar a = 6t + 2 of the subgroup check of SM9G2Group and a point Q of E'(Fp2), in G2 or not, which may be a private key: the time depends on a alone.
	static abstract void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result);
}
