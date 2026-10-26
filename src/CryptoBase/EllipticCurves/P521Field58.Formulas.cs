namespace CryptoBase.EllipticCurves;

// The point formulas with the reductions between steps left out where the sizes, defined in P521Field58.cs, allow. Inputs and outputs are of E: X3 and Y3 come from WeakReduce and Z3 from Multiply. Every subtrahend of SubtractUnreduced is an output of Multiply, Square or WeakReduce, and so of E.
// A value that Multiply or Square takes or gives by reference stays in memory, so the sums and differences between them go to locals of their own, which the JIT keeps in registers.
// Double and AddDistinct are not inlined: inlined into a caller, they leave too little of its inlining budget for the helpers that they inline themselves, which then become calls.
internal partial struct P521Field58
{
	// γ = Y², β = Xγ, δ = Z², α = 3(X − δ)(X + δ), X3 = α² − 8β, Y3 = α(4β − X3) − 8γ², Z3 = 2YZ.
	// 4β = X·4γ takes sizes 1 and 4, and 4γ² = (2γ)² size 2. X − δ is of size 3 and X + δ of 2; α, three times their product, is of size 3 and is reduced to E for α² and α(4β − X3). α² − 4β − 4β is of size 5, 4β − X3 of 3 and α(4β − X3) − 4γ² − 4γ² of 5. Z3 = 2Y·Z takes sizes 2 and 1.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	public static void Double(in JacobianPoint<P521Field58> value, out JacobianPoint<P521Field58> result)
	{
		Square(in value.Y, out P521Field58 gamma);
		AddUnreduced(in gamma, in gamma, out P521Field58 twoGamma);
		AddUnreduced(in twoGamma, in twoGamma, out P521Field58 fourGamma);
		Multiply(in value.X, in fourGamma, out P521Field58 fourBeta);
		Square(in value.Z, out P521Field58 delta);
		SubtractUnreduced(in value.X, in delta, out P521Field58 difference);
		AddUnreduced(in value.X, in delta, out P521Field58 sum);
		Multiply(in difference, in sum, out P521Field58 product);
		AddUnreduced(in product, in product, out P521Field58 twice);
		AddUnreduced(in product, in twice, out P521Field58 triple);
		WeakReduce(in triple, out P521Field58 alpha);
		AddUnreduced(in value.Y, in value.Y, out P521Field58 twoY);
		Multiply(in twoY, in value.Z, out result.Z);
		Square(in alpha, out P521Field58 square);
		SubtractUnreduced(in square, in fourBeta, out P521Field58 x3);
		SubtractUnreduced(in x3, in fourBeta, out x3);
		WeakReduce(in x3, out x3);
		result.X = x3;
		SubtractUnreduced(in fourBeta, in x3, out difference);
		Multiply(in alpha, in difference, out product);
		Square(in twoGamma, out square);
		SubtractUnreduced(in product, in square, out P521Field58 y3);
		SubtractUnreduced(in y3, in square, out y3);
		WeakReduce(in y3, out result.Y);
	}

	// H and R go through WeakReduce, which IsReducedZero requires, and stay reduced afterwards, so that the products of H keep within the sizes.
	// U1, U2, S1 and S2 are of E, so H = U2 − U1 is of size 3 and R = 2(S2 − S1) of 6; reduced, both are of E. 2H is of size 2, so Z3 = (Z1·Z2)·2H takes sizes 1 and 2, I = (2H)² sizes 2 and 2, and J, V and S1·J take E.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	public static ulong AddDistinct(in JacobianPoint<P521Field58> left, in JacobianPoint<P521Field58> right, out JacobianPoint<P521Field58> result)
	{
		Square(in left.Z, out P521Field58 z1z1);
		Square(in right.Z, out P521Field58 z2z2);
		Multiply(in left.X, in z2z2, out P521Field58 u1);
		Multiply(in right.X, in z1z1, out P521Field58 u2);
		SubtractUnreduced(in u2, in u1, out P521Field58 difference);
		WeakReduce(in difference, out P521Field58 h);
		Multiply(in z2z2, in right.Z, out z2z2);
		Multiply(in left.Y, in z2z2, out P521Field58 s1);
		Multiply(in z1z1, in left.Z, out z1z1);
		Multiply(in right.Y, in z1z1, out P521Field58 s2);
		SubtractUnreduced(in s2, in s1, out difference);
		AddUnreduced(in difference, in difference, out difference);
		WeakReduce(in difference, out P521Field58 r);
		ulong equal = IsReducedZero(in h) & IsReducedZero(in r);
		Multiply(in left.Z, in right.Z, out P521Field58 z3);
		AddUnreduced(in h, in h, out P521Field58 twoH);
		Multiply(in z3, in twoH, out result.Z);
		Square(in twoH, out P521Field58 i);
		Multiply(in h, in i, out P521Field58 j);
		Multiply(in u1, in i, out P521Field58 v);
		Multiply(in s1, in j, out s1);
		Combine(in r, in j, in v, in s1, out result.X, out result.Y);
		return equal;
	}

	// As above, with an affine right, whose coordinates are of E as well. H = X2·Z1² − X1 and R = 2(Y2·Z1³ − Y1) have the sizes above, Z3 = Z1·2H takes sizes 1 and 2, and V = X1·I and Y1·J take E.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	public static ulong AddDistinct(in JacobianPoint<P521Field58> left, in AffinePoint<P521Field58> right, out JacobianPoint<P521Field58> result)
	{
		Square(in left.Z, out P521Field58 zz);
		Multiply(in right.X, in zz, out P521Field58 u2);
		SubtractUnreduced(in u2, in left.X, out P521Field58 difference);
		WeakReduce(in difference, out P521Field58 h);
		Multiply(in zz, in left.Z, out zz);
		Multiply(in right.Y, in zz, out P521Field58 s2);
		SubtractUnreduced(in s2, in left.Y, out difference);
		AddUnreduced(in difference, in difference, out difference);
		WeakReduce(in difference, out P521Field58 r);
		ulong equal = IsReducedZero(in h) & IsReducedZero(in r);
		AddUnreduced(in h, in h, out P521Field58 twoH);
		Square(in twoH, out P521Field58 i);
		Multiply(in h, in i, out P521Field58 j);
		Multiply(in left.X, in i, out P521Field58 v);
		Multiply(in left.Y, in j, out P521Field58 yj);
		Multiply(in left.Z, in twoH, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
		return equal;
	}

	// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·SJ, for R, J, V and SJ of E. R² − J − 2V is of size 7, V − X3 of 3 and R(V − X3) − 2·SJ of 5.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void Combine(in P521Field58 r, in P521Field58 j, in P521Field58 v, in P521Field58 sj, out P521Field58 x, out P521Field58 y)
	{
		Square(in r, out P521Field58 square);
		SubtractUnreduced(in square, in j, out P521Field58 x3);
		SubtractUnreduced(in x3, in v, out x3);
		SubtractUnreduced(in x3, in v, out x3);
		WeakReduce(in x3, out x3);
		SubtractUnreduced(in v, in x3, out P521Field58 difference);
		Multiply(in r, in difference, out P521Field58 product);
		SubtractUnreduced(in product, in sj, out P521Field58 y3);
		SubtractUnreduced(in y3, in sj, out y3);
		WeakReduce(in y3, out y);
		x = x3;
	}
}
