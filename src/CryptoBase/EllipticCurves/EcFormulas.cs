namespace CryptoBase.EllipticCurves;

// The default IEcField point formulas, with the contracts stated there, with the reductions between steps left out: sums and differences go through AddUnreduced and SubtractUnreduced, and only the values that a zero test or a coordinate of the result needs go through WeakReduce. A field that takes these defaults states the bounds that keep each step within what the next one takes.
// Multiply and Square are not inlined, so a value that they take or give by reference stays in memory; the sums and differences between them go to locals of their own, which the JIT can keep in registers. Each formula writes a coordinate of the result only after its last read of the inputs, so that the result may be an input.
internal static class EcFormulas<TField> where TField : unmanaged, IEcField<TField>
{
	// γ = Y², β = Xγ, δ = Z², α = 3(X − δ)(X + δ), X3 = α² − 8β, Y3 = α(4β − X3) − 8γ², Z3 = 2YZ.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void Double(in JacobianPoint<TField> value, out JacobianPoint<TField> result)
	{
		TField.Square(in value.Y, out TField gamma);
		TField.AddUnreduced(in gamma, in gamma, out TField twoGamma);
		TField.Multiply(in value.X, in twoGamma, out TField product);
		TField.AddUnreduced(in product, in product, out TField fourBeta);
		TField.Square(in value.Z, out TField delta);
		TField.SubtractUnreduced(in value.X, in delta, out TField difference);
		TField.AddUnreduced(in value.X, in delta, out delta);
		TField.Multiply(in difference, in delta, out product);
		TField.AddUnreduced(in product, in product, out TField twice);
		TField.AddUnreduced(in product, in twice, out TField alpha);
		TField.Multiply(in value.Y, in value.Z, out product);
		TField.AddUnreduced(in product, in product, out result.Z);
		TField.Square(in alpha, out TField square);
		TField.SubtractUnreduced(in square, in fourBeta, out TField x3);
		TField.SubtractUnreduced(in x3, in fourBeta, out x3);
		TField.WeakReduce(in x3, out x3);
		result.X = x3;
		TField.SubtractUnreduced(in fourBeta, in x3, out difference);
		TField.Multiply(in alpha, in difference, out product);
		TField.Square(in twoGamma, out square);
		TField.AddUnreduced(in square, in square, out twice);
		TField.SubtractUnreduced(in product, in twice, out TField y3);
		TField.WeakReduce(in y3, out result.Y);
	}

	// H and R go through WeakReduce for the zero tests and stay reduced after them, which keeps the products of H within the form.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		TField.Square(in left.Z, out TField z1z1);
		TField.Square(in right.Z, out TField z2z2);
		TField.Multiply(in left.X, in z2z2, out TField u1);
		TField.Multiply(in right.X, in z1z1, out TField u2);
		TField.SubtractUnreduced(in u2, in u1, out TField difference);
		TField.WeakReduce(in difference, out TField h);
		TField.Multiply(in z2z2, in right.Z, out z2z2);
		TField.Multiply(in left.Y, in z2z2, out TField s1);
		TField.Multiply(in z1z1, in left.Z, out z1z1);
		TField.Multiply(in right.Y, in z1z1, out TField s2);
		TField.SubtractUnreduced(in s2, in s1, out difference);
		TField.AddUnreduced(in difference, in difference, out difference);
		TField.WeakReduce(in difference, out TField r);
		ulong equal = TField.IsReducedZero(in h) & TField.IsReducedZero(in r);
		TField.Multiply(in left.Z, in right.Z, out TField z3);
		TField.Multiply(in z3, in h, out z3);
		TField.AddUnreduced(in z3, in z3, out result.Z);
		TField.Square(in h, out TField square);
		TField.AddUnreduced(in square, in square, out TField twice);
		TField.AddUnreduced(in twice, in twice, out TField i);
		TField.Multiply(in h, in i, out TField j);
		TField.Multiply(in u1, in i, out TField v);
		TField.Multiply(in s1, in j, out s1);
		Combine(in r, in j, in v, in s1, out result.X, out result.Y);
		return equal;
	}

	// As above, with an affine right.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		TField.Square(in left.Z, out TField zz);
		TField.Multiply(in right.X, in zz, out TField u2);
		TField.SubtractUnreduced(in u2, in left.X, out TField difference);
		TField.WeakReduce(in difference, out TField h);
		TField.Multiply(in zz, in left.Z, out zz);
		TField.Multiply(in right.Y, in zz, out TField s2);
		TField.SubtractUnreduced(in s2, in left.Y, out difference);
		TField.AddUnreduced(in difference, in difference, out difference);
		TField.WeakReduce(in difference, out TField r);
		ulong equal = TField.IsReducedZero(in h) & TField.IsReducedZero(in r);
		TField.Square(in h, out TField square);
		TField.AddUnreduced(in square, in square, out TField twice);
		TField.AddUnreduced(in twice, in twice, out TField i);
		TField.Multiply(in h, in i, out TField j);
		TField.Multiply(in left.X, in i, out TField v);
		TField.Multiply(in left.Y, in j, out TField yj);
		TField.Multiply(in left.Z, in h, out h);
		TField.AddUnreduced(in h, in h, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
		return equal;
	}

	// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·SJ.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void Combine(in TField r, in TField j, in TField v, in TField sj, out TField x, out TField y)
	{
		TField.Square(in r, out TField square);
		TField.SubtractUnreduced(in square, in j, out TField x3);
		TField.SubtractUnreduced(in x3, in v, out x3);
		TField.SubtractUnreduced(in x3, in v, out x3);
		TField.WeakReduce(in x3, out x3);
		TField.SubtractUnreduced(in v, in x3, out TField difference);
		TField.Multiply(in r, in difference, out TField product);
		TField.SubtractUnreduced(in product, in sj, out TField y3);
		TField.SubtractUnreduced(in y3, in sj, out y3);
		TField.WeakReduce(in y3, out y);
		x = x3;
	}
}
