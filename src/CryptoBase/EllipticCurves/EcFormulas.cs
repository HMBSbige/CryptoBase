namespace CryptoBase.EllipticCurves;

// The default IEcField point formulas, with the contracts stated there, step by step through the field members, which give elements of the form that they take.
internal static class EcFormulas<TField> where TField : unmanaged, IEcField<TField>
{
	[SkipLocalsInit]
	internal static void Double(in JacobianPoint<TField> value, out JacobianPoint<TField> result)
	{
		TField.Square(in value.Y, out TField gamma);
		TField.Add(in gamma, in gamma, out TField twoGamma);
		TField.Multiply(in value.X, in twoGamma, out TField fourBeta);
		TField.Add(in fourBeta, in fourBeta, out fourBeta);
		TField.Square(in value.Z, out TField delta);
		TField.Subtract(in value.X, in delta, out TField alpha);
		TField.Add(in value.X, in delta, out delta);
		TField.Multiply(in alpha, in delta, out alpha);
		TField.Add(in alpha, in alpha, out delta);
		TField.Add(in alpha, in delta, out alpha);
		TField.Multiply(in value.Y, in value.Z, out TField z3);
		TField.Add(in z3, in z3, out result.Z);
		TField.Square(in alpha, out TField x3);
		TField.Subtract(in x3, in fourBeta, out x3);
		TField.Subtract(in x3, in fourBeta, out x3);
		TField.Subtract(in fourBeta, in x3, out fourBeta);
		TField.Multiply(in alpha, in fourBeta, out alpha);
		TField.Square(in twoGamma, out twoGamma);
		TField.Add(in twoGamma, in twoGamma, out twoGamma);
		TField.Subtract(in alpha, in twoGamma, out result.Y);
		result.X = x3;
	}

	[SkipLocalsInit]
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		TField.Square(in left.Z, out TField z1z1);
		TField.Square(in right.Z, out TField z2z2);
		TField.Multiply(in left.X, in z2z2, out TField u1);
		TField.Multiply(in right.X, in z1z1, out TField h);
		TField.Subtract(in h, in u1, out h);
		TField.Multiply(in z2z2, in right.Z, out z2z2);
		TField.Multiply(in left.Y, in z2z2, out TField s1);
		TField.Multiply(in z1z1, in left.Z, out z1z1);
		TField.Multiply(in right.Y, in z1z1, out TField r);
		TField.Subtract(in r, in s1, out r);
		TField.Add(in r, in r, out r);
		ulong equal = TField.IsZero(in h) & TField.IsZero(in r);
		TField.Multiply(in left.Z, in right.Z, out TField z3);
		TField.Multiply(in z3, in h, out z3);
		TField.Add(in z3, in z3, out result.Z);
		TField.Square(in h, out TField i);
		TField.Add(in i, in i, out i);
		TField.Add(in i, in i, out i);
		TField.Multiply(in h, in i, out TField j);
		TField.Multiply(in u1, in i, out TField v);
		TField.Multiply(in s1, in j, out s1);
		Combine(in r, in j, in v, in s1, out result.X, out result.Y);
		return equal;
	}

	[SkipLocalsInit]
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		TField.Square(in left.Z, out TField zz);
		TField.Multiply(in right.X, in zz, out TField h);
		TField.Subtract(in h, in left.X, out h);
		TField.Multiply(in zz, in left.Z, out zz);
		TField.Multiply(in right.Y, in zz, out TField r);
		TField.Subtract(in r, in left.Y, out r);
		TField.Add(in r, in r, out r);
		ulong equal = TField.IsZero(in h) & TField.IsZero(in r);
		TField.Square(in h, out TField i);
		TField.Add(in i, in i, out i);
		TField.Add(in i, in i, out i);
		TField.Multiply(in h, in i, out TField j);
		TField.Multiply(in left.X, in i, out TField v);
		TField.Multiply(in left.Y, in j, out TField yj);
		TField.Multiply(in left.Z, in h, out h);
		TField.Add(in h, in h, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
		return equal;
	}

	[SkipLocalsInit]
	private static void Combine(in TField r, in TField j, in TField v, in TField sj, out TField x, out TField y)
	{
		TField.Square(in r, out TField x3);
		TField.Subtract(in x3, in j, out x3);
		TField.Subtract(in x3, in v, out x3);
		TField.Subtract(in x3, in v, out x3);
		TField.Subtract(in v, in x3, out TField y3);
		TField.Multiply(in r, in y3, out y3);
		TField.Subtract(in y3, in sj, out y3);
		TField.Subtract(in y3, in sj, out y);
		x = x3;
	}
}
