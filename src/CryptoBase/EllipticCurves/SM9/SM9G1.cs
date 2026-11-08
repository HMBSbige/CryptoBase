namespace CryptoBase.EllipticCurves.SM9;

// G1 = E(Fp) for E: y² = x³ + 5, of prime order N with the generator P1 of GM/T 0044.5 §3.1, for the protocols of GM/T 0044.2 to 0044.4. Points are affine, with reduced coordinates in Montgomery form, and never the point at infinity; scalars are plain values below N. The cofactor is 1, so every point of the curve lies in G1.
internal static class SM9G1
{
	// 04 ‖ x ‖ y, the uncompressed form of GM/T 0044.1 §7.2.8.
	internal const int EncodedLength = 1 + 2 * SM9Fp.ByteLength;

	internal static ref readonly SM9AffinePoint<SM9Fp> Generator => ref SM9G1Group.Generator;

	// The form must be 04 ‖ x ‖ y with x and y below p and the point on the curve. The checks branch on whether the encoding is valid alone, so the input may be a private key, whose coordinates in plain form are erased.
	[SkipLocalsInit]
	internal static bool TryDecode(ReadOnlySpan<byte> source, out SM9AffinePoint<SM9Fp> result)
	{
		if (source.Length != EncodedLength || source[0] is not 0x04)
		{
			result = default;
			return false;
		}

		bool valid = SM9Fp.TryImport(source.Slice(1, SM9Fp.ByteLength), out SM9Fp x) & SM9Fp.TryImport(source.Slice(1 + SM9Fp.ByteLength), out SM9Fp y);
		SM9Fp.ToMontgomery(in x, out result.X);
		SM9Fp.ToMontgomery(in y, out result.Y);
		x.ZeroMemory();
		y.ZeroMemory();

		if (!valid || !SM9Curve<SM9Fp>.IsOnCurve(in result))
		{
			result = default;
			return false;
		}

		return true;
	}

	internal static void Encode(in SM9AffinePoint<SM9Fp> point, Span<byte> destination)
	{
		Debug.Assert(destination.Length is EncodedLength);

		destination[0] = 0x04;
		SM9Fp.ExportPlain(in point.X, destination.Slice(1, SM9Fp.ByteLength));
		SM9Fp.ExportPlain(in point.Y, destination.Slice(1 + SM9Fp.ByteLength));
	}

	// k·P1 for k in [1, N − 1]; k = 0 gives (0, 0), not a point. Neither the time nor the addresses depend on k, and the projective product is erased.
	internal static void MultiplyBase(in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp> result)
	{
		Multiply(SM9G1Group.BaseTable, in scalar, out result);
	}

	// k·G for the table of a point G of G1, which may be secret, and k in [1, N − 1], as above; neither the time nor the addresses depend on G either.
	internal static void Multiply(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp> result)
	{
		SM9KernelDispatch.MultiplyBaseG1(table, in scalar, out SM9Point<SM9Fp> product);
		_ = SM9Curve<SM9Fp>.ToAffine(in product, out result);
		product.ZeroMemory();
	}

	// k·P for P of G1 and k in [1, N − 1], as above.
	internal static void Multiply(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp> result)
	{
		SM9KernelDispatch.MultiplyG1(in point, in scalar, out SM9Point<SM9Fp> product);
		_ = SM9Curve<SM9Fp>.ToAffine(in product, out result);
		product.ZeroMemory();
	}

	// k·P for a public P of G1 and a public k in [1, N − 1], in variable time, in projective form.
	internal static void MultiplyVariableTime(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9KernelDispatch.MultiplyVariableTimeG1(in point, in scalar, out result);
	}

	// a·P1 + b·Q for Q of G1, from the table of Q if there is one, which must be that of point; returns ulong.MaxValue, with result (0, 0), if the sum is the point at infinity, and 0 otherwise. Neither the time nor the addresses depend on a, b or Q, and the projective products are erased.
	[SkipLocalsInit]
	internal static ulong MultiplyBaseSum(in FieldElement<SM9Order> baseScalar, in SM9AffinePoint<SM9Fp> point, SM9BaseTable<SM9Fp>? table, in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp> result)
	{
		Unsafe.SkipInit(out SM9Point<SM9Fp> sum);

		if (table is null)
		{
			SM9KernelDispatch.MultiplyBaseG1(SM9G1Group.BaseTable, in baseScalar, out sum);
			SM9KernelDispatch.MultiplyG1(in point, in scalar, out SM9Point<SM9Fp> product);
			SM9Curve<SM9Fp>.Add(in sum, in product, out sum);
			product.ZeroMemory();
		}
		else
		{
			SM9KernelDispatch.MultiplyBaseSumG1(SM9G1Group.BaseTable, in baseScalar, table, in scalar, out sum);
		}

		ulong infinity = SM9Curve<SM9Fp>.ToAffine(in sum, out result);
		sum.ZeroMemory();
		return infinity;
	}

	// k·P1 + Q for a public k and Q of G1. Returns false, with result 0, if the sum is the point at infinity.
	internal static bool MultiplyBaseAddVariableTime(in FieldElement<SM9Order> scalar, in SM9AffinePoint<SM9Fp> point, out SM9AffinePoint<SM9Fp> result)
	{
		SM9Curve<SM9Fp>.FromAffine(in point, out SM9Point<SM9Fp> addend);
		SM9KernelDispatch.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out SM9Point<SM9Fp> sum);
		return SM9Curve<SM9Fp>.ToAffineVariableTime(in sum, out result);
	}

	// As above in projective form, whose Z is 0 for the point at infinity.
	internal static void MultiplyBaseAddVariableTime(in FieldElement<SM9Order> scalar, in SM9AffinePoint<SM9Fp> point, out SM9Point<SM9Fp> result)
	{
		SM9Curve<SM9Fp>.FromAffine(in point, out SM9Point<SM9Fp> addend);
		SM9KernelDispatch.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
	}
}
