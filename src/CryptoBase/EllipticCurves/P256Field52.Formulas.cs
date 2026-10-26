namespace CryptoBase.EllipticCurves;

// The IEcField point formulas with the reductions between steps left out where the bounds allow. Inputs and outputs are of E: X3 and Y3 come from WeakReduce, and Z3 is twice a product of inputs of E, which has limbs 0 to 3 below 2^52 and limb 4 below 2^49.
// The bounds below hold for any inputs of E: every input of Multiply and Square has limbs below 2^55, every input of WeakReduce limbs below 2^56, and every subtrahend of SubtractUnreduced is of E. Other intermediate values need not be of E.
// Multiply and Square are not inlined, so a value that they take or give by reference stays in memory; the sums and differences between them go to locals of their own, which the JIT can keep in registers.
internal partial struct P256Field52
{
	// γ = Y², β = Xγ, δ = Z², α = 3(X − δ)(X + δ), X3 = α² − 8β, Y3 = α(4β − X3) − 8γ², Z3 = 2YZ. The result may be the input.
	// γ, β and δ are below 2.1p, and 2γ, 4β and 8γ², each twice a product of inputs of E, are of E and below 4.1p. X − δ is below 9.1p in limbs below 2^55 and X + δ below 6.1p in limbs below 2^54. Their product is below 4.4p, so its limb 4 may exceed 2^50 and it is not of E; it goes only into α, below 13.2p in limbs below 2^54, which only Multiply and Square take. α² − 8β is below 21.8p in limbs below 2^55. 4β − X3 is below 9.1p in limbs below 2^55, α(4β − X3) below 8.4p, and that less 8γ² below 13.4p in limbs below 2^54.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Double(in JacobianPoint<P256Field52> value, out JacobianPoint<P256Field52> result)
	{
		Square(in value.Y, out P256Field52 gamma);
		AddUnreduced(in gamma, in gamma, out P256Field52 twoGamma);
		Multiply(in value.X, in twoGamma, out P256Field52 product);
		AddUnreduced(in product, in product, out P256Field52 fourBeta);
		Square(in value.Z, out P256Field52 delta);
		SubtractUnreduced(in value.X, in delta, out P256Field52 difference);
		AddUnreduced(in value.X, in delta, out delta);
		Multiply(in difference, in delta, out product);
		AddUnreduced(in product, in product, out P256Field52 twice);
		AddUnreduced(in product, in twice, out P256Field52 alpha);
		Multiply(in value.Y, in value.Z, out product);
		AddUnreduced(in product, in product, out result.Z);
		Square(in alpha, out P256Field52 square);
		SubtractUnreduced(in square, in fourBeta, out P256Field52 x3);
		SubtractUnreduced(in x3, in fourBeta, out x3);
		WeakReduce(in x3, out x3);
		result.X = x3;
		SubtractUnreduced(in fourBeta, in x3, out difference);
		Multiply(in alpha, in difference, out product);
		Square(in twoGamma, out square);
		AddUnreduced(in square, in square, out twice);
		SubtractUnreduced(in product, in twice, out P256Field52 y3);
		WeakReduce(in y3, out result.Y);
	}

	// H and R go through WeakReduce for the zero tests and stay reduced after them, which keeps the products of H within E.
	// U1, U2, S1 and S2 are below 1.6p, so H is below 6.6p in limbs below 2^54 and 2R below 12.8p in limbs below 2^55; reduced, both are below 1.1p in limbs below 2^52. Z1·Z2·H is below 1.2p, so Z3 is below 2.3p. I = 4H² is below 4.3p in limbs below 2^54, not of E, and goes only into Multiply; J, V and S1·J are below 1.4p.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static ulong AddDistinct(in JacobianPoint<P256Field52> left, in JacobianPoint<P256Field52> right, out JacobianPoint<P256Field52> result)
	{
		Square(in left.Z, out P256Field52 z1z1);
		Square(in right.Z, out P256Field52 z2z2);
		Multiply(in left.X, in z2z2, out P256Field52 u1);
		Multiply(in right.X, in z1z1, out P256Field52 u2);
		SubtractUnreduced(in u2, in u1, out P256Field52 difference);
		WeakReduce(in difference, out P256Field52 h);
		Multiply(in z2z2, in right.Z, out z2z2);
		Multiply(in left.Y, in z2z2, out P256Field52 s1);
		Multiply(in z1z1, in left.Z, out z1z1);
		Multiply(in right.Y, in z1z1, out P256Field52 s2);
		SubtractUnreduced(in s2, in s1, out difference);
		AddUnreduced(in difference, in difference, out difference);
		WeakReduce(in difference, out P256Field52 r);
		ulong equal = IsReducedZero(in h) & IsReducedZero(in r);
		Multiply(in left.Z, in right.Z, out P256Field52 z3);
		Multiply(in z3, in h, out z3);
		AddUnreduced(in z3, in z3, out result.Z);
		Square(in h, out P256Field52 square);
		AddUnreduced(in square, in square, out P256Field52 twice);
		AddUnreduced(in twice, in twice, out P256Field52 i);
		Multiply(in h, in i, out P256Field52 j);
		Multiply(in u1, in i, out P256Field52 v);
		Multiply(in s1, in j, out s1);
		Combine(in r, in j, in v, in s1, out result.X, out result.Y);
		return equal;
	}

	// As above, with an affine right, whose coordinates are of E as well. H = X2·Z1² − X1 and 2R = 2(Y2·Z1³ − Y1) have the bounds above, Z1·H is below 1.3p, so Z3 is below 2.6p, and V = X1·I and Y1·J are below 2.1p.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static ulong AddDistinct(in JacobianPoint<P256Field52> left, in AffinePoint<P256Field52> right, out JacobianPoint<P256Field52> result)
	{
		Square(in left.Z, out P256Field52 zz);
		Multiply(in right.X, in zz, out P256Field52 u2);
		SubtractUnreduced(in u2, in left.X, out P256Field52 difference);
		WeakReduce(in difference, out P256Field52 h);
		Multiply(in zz, in left.Z, out zz);
		Multiply(in right.Y, in zz, out P256Field52 s2);
		SubtractUnreduced(in s2, in left.Y, out difference);
		AddUnreduced(in difference, in difference, out difference);
		WeakReduce(in difference, out P256Field52 r);
		ulong equal = IsReducedZero(in h) & IsReducedZero(in r);
		Square(in h, out P256Field52 square);
		AddUnreduced(in square, in square, out P256Field52 twice);
		AddUnreduced(in twice, in twice, out P256Field52 i);
		Multiply(in h, in i, out P256Field52 j);
		Multiply(in left.X, in i, out P256Field52 v);
		Multiply(in left.Y, in j, out P256Field52 yj);
		Multiply(in left.Z, in h, out h);
		AddUnreduced(in h, in h, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
		return equal;
	}

	// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·SJ, for R below 1.1p and J, V and SJ below 2.1p, in limbs 0 to 3 below 2^52 and limb 4 below 2^50. R² is below 1.1p and R² − J − 2V below 16.1p in limbs below 2^56. V − X3 is below 7.1p in limbs below 2^54, R(V − X3) below 1.5p, and that less 2·SJ below 11.5p in limbs below 2^55.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void Combine(in P256Field52 r, in P256Field52 j, in P256Field52 v, in P256Field52 sj, out P256Field52 x, out P256Field52 y)
	{
		Square(in r, out P256Field52 square);
		SubtractUnreduced(in square, in j, out P256Field52 x3);
		SubtractUnreduced(in x3, in v, out x3);
		SubtractUnreduced(in x3, in v, out x3);
		WeakReduce(in x3, out x3);
		SubtractUnreduced(in v, in x3, out P256Field52 difference);
		Multiply(in r, in difference, out P256Field52 product);
		SubtractUnreduced(in product, in sj, out P256Field52 y3);
		SubtractUnreduced(in y3, in sj, out y3);
		WeakReduce(in y3, out y);
		x = x3;
	}
}
