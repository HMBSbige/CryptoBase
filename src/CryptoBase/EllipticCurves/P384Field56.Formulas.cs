namespace CryptoBase.EllipticCurves;

// The point formulas, with the reductions between steps left out where the bounds allow. Inputs are of E and so are the outputs: X3 and Y3 come from WeakReduce, and Z3 is twice an output of Multiply, which has limbs 0 to 5 below 2^56 and limb 6 below 2^49 for the inputs here. The bounds below hold for any inputs of E: every input of Multiply has limbs below 5·2^56 and a value below 9p, every input of Square limbs below 3·2^56, every subtrahend of SubtractUnreduced is of E, as outputs of Multiply, Square and WeakReduce and their doubles below 2.2p are, and every input of WeakReduce has limbs below 2^60.
// A value that Multiply or Square takes or gives by reference stays in memory, so the sums and differences between them get locals of their own, which can stay in registers. Each formula writes a coordinate of the result only after its last read of the inputs, so that the result may be an input.
internal partial struct P384Field56
{
	// γ = Y², β = Xγ, δ = Z², α = 3(X − δ)(X + δ), X3 = α² − 8β, Y3 = α(4β − X3) − 8γ², Z3 = 2YZ.
	// γ, β and δ are below 1.1p in limbs below 2^56, and 2γ and 4β below 2.2p in limbs below 2^57. X − δ is below 9p in limbs below 5·2^56 and X + δ below 5.1p in limbs below 3·2^56, so their product is below 1.2p and α below 3.6p in limbs below 3·2^56. α² − 8β is below 11.1p in limbs below 2^59. 4β − X3 is below 7.1p in limbs below 5·2^56, α(4β − X3) below 1.1p, and that less 8γ² below 6.1p in limbs below 2^58.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Double(in JacobianPoint<P384Field56> value, out JacobianPoint<P384Field56> result)
	{
		Square(in value.Y, out P384Field56 gamma);
		AddUnreduced(in gamma, in gamma, out P384Field56 twoGamma);
		Multiply(in value.X, in twoGamma, out P384Field56 product);
		AddUnreduced(in product, in product, out P384Field56 fourBeta);
		Square(in value.Z, out P384Field56 delta);
		SubtractUnreduced(in value.X, in delta, out P384Field56 difference);
		AddUnreduced(in value.X, in delta, out delta);
		Multiply(in difference, in delta, out product);
		AddUnreduced(in product, in product, out P384Field56 twice);
		AddUnreduced(in product, in twice, out P384Field56 alpha);
		Multiply(in value.Y, in value.Z, out product);
		AddUnreduced(in product, in product, out result.Z);
		Square(in alpha, out P384Field56 square);
		SubtractUnreduced(in square, in fourBeta, out P384Field56 x3);
		SubtractUnreduced(in x3, in fourBeta, out x3);
		WeakReduce(in x3, out x3);
		result.X = x3;
		SubtractUnreduced(in fourBeta, in x3, out difference);
		Multiply(in alpha, in difference, out product);
		Square(in twoGamma, out square);
		AddUnreduced(in square, in square, out twice);
		SubtractUnreduced(in product, in twice, out P384Field56 y3);
		WeakReduce(in y3, out result.Y);
	}

	// H and R go through WeakReduce for the zero tests and stay reduced after them, so that the products of H keep within E.
	// U1, U2, S1 and S2 are below 1.1p in limbs below 2^56, so H is below 6.1p in limbs below 2^58 and 2R below 12.1p in limbs below 2^59; reduced, both are below 2^384 + 2^342 in limbs below 2^56. Z1·Z2·H is below 1.1p, so Z3 is below 2.1p. I = 4H² is below 4.1p in limbs below 2^58, and J, V and S1·J are below 1.1p.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static ulong AddDistinct(in JacobianPoint<P384Field56> left, in JacobianPoint<P384Field56> right, out JacobianPoint<P384Field56> result)
	{
		Square(in left.Z, out P384Field56 z1z1);
		Square(in right.Z, out P384Field56 z2z2);
		Multiply(in left.X, in z2z2, out P384Field56 u1);
		Multiply(in right.X, in z1z1, out P384Field56 u2);
		SubtractUnreduced(in u2, in u1, out P384Field56 difference);
		WeakReduce(in difference, out P384Field56 h);
		Multiply(in z2z2, in right.Z, out z2z2);
		Multiply(in left.Y, in z2z2, out P384Field56 s1);
		Multiply(in z1z1, in left.Z, out z1z1);
		Multiply(in right.Y, in z1z1, out P384Field56 s2);
		SubtractUnreduced(in s2, in s1, out difference);
		AddUnreduced(in difference, in difference, out difference);
		WeakReduce(in difference, out P384Field56 r);
		ulong equal = IsReducedZero(in h) & IsReducedZero(in r);
		Multiply(in left.Z, in right.Z, out P384Field56 z3);
		Multiply(in z3, in h, out z3);
		AddUnreduced(in z3, in z3, out result.Z);
		Square(in h, out P384Field56 square);
		AddUnreduced(in square, in square, out P384Field56 twice);
		AddUnreduced(in twice, in twice, out P384Field56 i);
		Multiply(in h, in i, out P384Field56 j);
		Multiply(in u1, in i, out P384Field56 v);
		Multiply(in s1, in j, out s1);
		Combine(in r, in j, in v, in s1, out result.X, out result.Y);
		return equal;
	}

	// As above, with an affine right, whose coordinates are of E as well. H = X2·Z1² − X1 and 2R = 2(Y2·Z1³ − Y1) have the bounds above, Z1·H is below 1.1p, so Z3 is below 2.1p, and V = X1·I and Y1·J are below 1.1p.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static ulong AddDistinct(in JacobianPoint<P384Field56> left, in AffinePoint<P384Field56> right, out JacobianPoint<P384Field56> result)
	{
		Square(in left.Z, out P384Field56 zz);
		Multiply(in right.X, in zz, out P384Field56 u2);
		SubtractUnreduced(in u2, in left.X, out P384Field56 difference);
		WeakReduce(in difference, out P384Field56 h);
		Multiply(in zz, in left.Z, out zz);
		Multiply(in right.Y, in zz, out P384Field56 s2);
		SubtractUnreduced(in s2, in left.Y, out difference);
		AddUnreduced(in difference, in difference, out difference);
		WeakReduce(in difference, out P384Field56 r);
		ulong equal = IsReducedZero(in h) & IsReducedZero(in r);
		Square(in h, out P384Field56 square);
		AddUnreduced(in square, in square, out P384Field56 twice);
		AddUnreduced(in twice, in twice, out P384Field56 i);
		Multiply(in h, in i, out P384Field56 j);
		Multiply(in left.X, in i, out P384Field56 v);
		Multiply(in left.Y, in j, out P384Field56 yj);
		Multiply(in left.Z, in h, out h);
		AddUnreduced(in h, in h, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
		return equal;
	}

	// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·SJ, for R below 2^384 + 2^342 and J, V and SJ below 1.1p, all in limbs below 2^56. R² is below 1.1p and R² − J − 2V below 16.1p in limbs below 10·2^56. V − X3 is below 6.1p in limbs below 2^58, R(V − X3) below 1.1p, and that less 2·SJ below 11.1p in limbs below 2^59.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void Combine(in P384Field56 r, in P384Field56 j, in P384Field56 v, in P384Field56 sj, out P384Field56 x, out P384Field56 y)
	{
		Square(in r, out P384Field56 square);
		SubtractUnreduced(in square, in j, out P384Field56 x3);
		SubtractUnreduced(in x3, in v, out x3);
		SubtractUnreduced(in x3, in v, out x3);
		WeakReduce(in x3, out x3);
		SubtractUnreduced(in v, in x3, out P384Field56 difference);
		Multiply(in r, in difference, out P384Field56 product);
		SubtractUnreduced(in product, in sj, out P384Field56 y3);
		SubtractUnreduced(in y3, in sj, out y3);
		WeakReduce(in y3, out y);
		x = x3;
	}
}
