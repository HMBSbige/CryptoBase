namespace CryptoBase.EllipticCurves.SM9;

// Fp2 = Fp[u]/(u² + 2) of GM/T 0044.5 §3.2, the element A0 + A1·u, both reduced SM9Fp elements. Every member takes and gives reduced coefficients. The sums, differences and small multiples are not inlined: each takes a weak reduction per coefficient, and inlined into the formulas of the twist and the Miller loop they would leave those too long for the op cache. No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal struct SM9Fp2 : ISM9Field<SM9Fp2>
{
	internal SM9Fp A0;
	internal SM9Fp A1;

	internal const int ByteLength = 2 * SM9Fp.ByteLength;

	private static readonly SM9Fp2 OneValue = new() { A0 = SM9Fp.One };

	// 5u, the coefficient of the twist.
	private static readonly SM9Fp2 BValue = new() { A1 = SM9Fp.B };

	public static ref readonly SM9Fp2 One => ref OneValue;

	public static ref readonly SM9Fp2 B => ref BValue;

	// Karatsuba with one reduction per coefficient: a0b0 − 2a1b1 + 11p² and (a0 + a1)(b0 + b1) − a0b0 − a1b1 = a0b1 + a1b0. For reduced inputs each product is below 5.1p² and the sums below 4.5p, so the two values are below 16.1p² and 10.2p².
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	public static void Multiply(in SM9Fp2 left, in SM9Fp2 right, out SM9Fp2 result)
	{
		SM9Fp.MultiplyWide(in left.A0, in right.A0, out SM9FpWide p0);
		SM9Fp.MultiplyWide(in left.A1, in right.A1, out SM9FpWide p1);
		SM9Fp.AddUnreduced(in left.A0, in left.A1, out SM9Fp leftSum);
		SM9Fp.AddUnreduced(in right.A0, in right.A1, out SM9Fp rightSum);
		SM9Fp.MultiplyWide(in leftSum, in rightSum, out SM9FpWide p2);
		SM9FpWide.SubtractTwice(in p0, in p1, out SM9FpWide c0);
		SM9FpWide.Subtract(in p2, in p0, out p2);
		SM9FpWide.Subtract(in p2, in p1, out p2);
		Unsafe.SkipInit(out result);
		SM9Fp.Reduce(in c0, out result.A0);
		SM9Fp.Reduce(in p2, out result.A1);
	}

	// a0² − 2a1² + 11p² and (a0 + a1)² − a0² − a1² = 2a0a1, below 16.1p² and 10.2p².
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	public static void Square(in SM9Fp2 value, out SM9Fp2 result)
	{
		SM9Fp.SquareWide(in value.A0, out SM9FpWide s0);
		SM9Fp.SquareWide(in value.A1, out SM9FpWide s1);
		SM9Fp.AddUnreduced(in value.A0, in value.A1, out SM9Fp sum);
		SM9Fp.SquareWide(in sum, out SM9FpWide s2);
		SM9FpWide.SubtractTwice(in s0, in s1, out SM9FpWide c0);
		SM9FpWide.Subtract(in s2, in s0, out s2);
		SM9FpWide.Subtract(in s2, in s1, out s2);
		Unsafe.SkipInit(out result);
		SM9Fp.Reduce(in c0, out result.A0);
		SM9Fp.Reduce(in s2, out result.A1);
	}

	// The product as integer polynomials before reduction, a0b0 − 2a1b1 and (a0 + a1)(b0 + b1) − a0b0 − a1b1 = a0b1 + a1b0. For limbs below 2^53, as a sum of two reduced elements has, the columns of a0b0 − 2a1b1 are below 2^58.2 and those of a0b1 + a1b0 below 2^58.9 in magnitude; for reduced inputs, below 2^56.9 and 2^57.3.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	internal static void MultiplyWide(in SM9Fp2 left, in SM9Fp2 right, out SM9Fp2Wide result)
	{
		SM9Fp.MultiplyWide(in left.A0, in right.A0, out SM9FpWide p0);
		SM9Fp.MultiplyWide(in left.A1, in right.A1, out SM9FpWide p1);
		SM9Fp.AddUnreduced(in left.A0, in left.A1, out SM9Fp leftSum);
		SM9Fp.AddUnreduced(in right.A0, in right.A1, out SM9Fp rightSum);
		SM9Fp.MultiplyWide(in leftSum, in rightSum, out SM9FpWide p2);
		SM9FpWide.SubtractTwiceUnbalanced(in p0, in p1, out result.W0);
		SM9FpWide.Subtract(in p2, in p0, out p2);
		SM9FpWide.Subtract(in p2, in p1, out result.W1);
	}

	// The square as integer polynomials, a0² − 2a1² and 2a0a1, with the bounds of MultiplyWide.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	internal static void SquareWide(in SM9Fp2 value, out SM9Fp2Wide result)
	{
		SM9Fp.SquareWide(in value.A0, out SM9FpWide s0);
		SM9Fp.SquareWide(in value.A1, out SM9FpWide s1);
		SM9Fp.AddUnreduced(in value.A0, in value.A1, out SM9Fp sum);
		SM9Fp.SquareWide(in sum, out SM9FpWide s2);
		SM9FpWide.SubtractTwiceUnbalanced(in s0, in s1, out result.W0);
		SM9FpWide.Subtract(in s2, in s0, out s2);
		SM9FpWide.Subtract(in s2, in s1, out result.W1);
	}

	// a + b − 2c for reduced inputs.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void SumMinusTwice(in SM9Fp2 a, in SM9Fp2 b, in SM9Fp2 c, out SM9Fp2 result)
	{
		SM9Fp a1 = a.A1;
		SM9Fp b1 = b.A1;
		SM9Fp c1 = c.A1;
		Unsafe.SkipInit(out result);
		SM9Fp.SumMinusTwice(in a.A0, in b.A0, in c.A0, out result.A0);
		SM9Fp.SumMinusTwice(in a1, in b1, in c1, out result.A1);
	}

	// left + 3p − right in each coefficient, limb by limb, for a reduced right: below left + 3p, in limbs grown by below 2^53.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractUnreduced(in SM9Fp2 left, in SM9Fp2 right, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.SubtractUnreduced(in left.A0, in right.A0, out result.A0);
		SM9Fp.SubtractUnreduced(in left.A1, in right.A1, out result.A1);
	}

	// Limb by limb, without carries.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddUnreduced(in SM9Fp2 left, in SM9Fp2 right, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.AddUnreduced(in left.A0, in right.A0, out result.A0);
		SM9Fp.AddUnreduced(in left.A1, in right.A1, out result.A1);
	}

	// right may be a coefficient of result: the product into that coefficient comes last, after the other one has read right, and SM9Fp.Multiply reads its inputs before it writes. A1 comes first just for right = result.A0, out of line, so that the other callers copy nothing and pay a comparison at most, which the JIT drops where it tells right from result.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyByFp(in SM9Fp2 left, in SM9Fp right, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);

		if (Unsafe.AreSame(in right, in result.A0))
		{
			MultiplyByA0(in left, ref result);
			return;
		}

		SM9Fp.Multiply(in left.A0, in right, out result.A0);
		SM9Fp.Multiply(in left.A1, in right, out result.A1);
	}

	// result = left·result.A0 for MultiplyByFp.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void MultiplyByA0(in SM9Fp2 left, ref SM9Fp2 result)
	{
		SM9Fp.Multiply(in left.A1, in result.A0, out result.A1);
		SM9Fp.Multiply(in left.A0, in result.A0, out result.A0);
	}

	// value·u = −2a1 + a0·u: −2a1 is 2(3p − a1), below 6p.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void MultiplyByU(in SM9Fp2 value, out SM9Fp2 result)
	{
		SM9Fp zero = default;
		SM9Fp.SubtractUnreduced(in zero, in value.A1, out SM9Fp negated);
		SM9Fp a0 = value.A0;
		Unsafe.SkipInit(out result);
		SM9Fp.Add(in negated, in negated, out result.A0);
		result.A1 = a0;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	public static void Add(in SM9Fp2 left, in SM9Fp2 right, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.Add(in left.A0, in right.A0, out result.A0);
		SM9Fp.Add(in left.A1, in right.A1, out result.A1);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	public static void Subtract(in SM9Fp2 left, in SM9Fp2 right, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.Subtract(in left.A0, in right.A0, out result.A0);
		SM9Fp.Subtract(in left.A1, in right.A1, out result.A1);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	public static void Negate(in SM9Fp2 value, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.Negate(in value.A0, out result.A0);
		SM9Fp.Negate(in value.A1, out result.A1);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Double(in SM9Fp2 value, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.Add(in value.A0, in value.A0, out result.A0);
		SM9Fp.Add(in value.A1, in value.A1, out result.A1);
	}

	// k up to 9.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	public static void MultiplySmall(in SM9Fp2 value, uint k, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.MultiplySmall(in value.A0, k, out result.A0);
		SM9Fp.MultiplySmall(in value.A1, k, out result.A1);
	}

	// 15u·value for b = 5u.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	public static void MultiplyByThreeB(in SM9Fp2 value, out SM9Fp2 result)
	{
		MultiplySmall(in value, 3, out result);
		MultiplySmall(in result, 5, out result);
		MultiplyByU(in result, out result);
	}

	// a0 − a1·u, the image of the p-power Frobenius, as u^p = −u.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Conjugate(in SM9Fp2 value, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		result.A0 = value.A0;
		SM9Fp.Negate(in value.A1, out result.A1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong IsZero(in SM9Fp2 value)
	{
		return SM9Fp.IsZero(in value.A0) & SM9Fp.IsZero(in value.A1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong AreEqual(in SM9Fp2 left, in SM9Fp2 right)
	{
		return SM9Fp.AreEqual(in left.A0, in right.A0) & SM9Fp.AreEqual(in left.A1, in right.A1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSelect(ulong mask, in SM9Fp2 whenSet, in SM9Fp2 whenClear, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.ConditionalSelect(mask, in whenSet.A0, in whenClear.A0, out result.A0);
		SM9Fp.ConditionalSelect(mask, in whenSet.A1, in whenClear.A1, out result.A1);
	}

	// (a0 − a1·u)/(a0² + 2a1²), the norm below 15.2p². 0 gives 0.
	[SkipLocalsInit]
	public static void Invert(in SM9Fp2 value, out SM9Fp2 result)
	{
		Norm(in value, out SM9Fp norm);
		SM9Fp.Invert(in norm, out norm);
		Scale(in value, in norm, out result);
		norm.ZeroMemory();
	}

	// As Invert, for a public value.
	[SkipLocalsInit]
	public static void InvertVariableTime(in SM9Fp2 value, out SM9Fp2 result)
	{
		Norm(in value, out SM9Fp norm);
		SM9Fp.InvertVariableTime(in norm, out norm);
		Scale(in value, in norm, out result);
	}

	// The element of plain values in Montgomery form.
	[SkipLocalsInit]
	internal static void ToMontgomery(in SM9Fp2 value, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.ToMontgomery(in value.A0, out result.A0);
		SM9Fp.ToMontgomery(in value.A1, out result.A1);
	}

	// Reads A1 and then A0 in 32 big-endian bytes each, the order of GM/T 0044.1 §7.2.7, as plain values; if either is not below p, the result is 0.
	[SkipLocalsInit]
	internal static bool TryImport(ReadOnlySpan<byte> source, out SM9Fp2 result)
	{
		Debug.Assert(source.Length is ByteLength);

		Unsafe.SkipInit(out result);
		bool valid = SM9Fp.TryImport(source.Slice(0, SM9Fp.ByteLength), out result.A1);
		valid &= SM9Fp.TryImport(source.Slice(SM9Fp.ByteLength), out result.A0);

		if (!valid)
		{
			result = default;
		}

		return valid;
	}

	// Writes the plain value of a Montgomery form, A1 and then A0, as GM/T 0044.1 §7.2.6 orders them.
	internal static void ExportPlain(in SM9Fp2 value, Span<byte> destination)
	{
		Debug.Assert(destination.Length is ByteLength);

		SM9Fp.ExportPlain(in value.A1, destination.Slice(0, SM9Fp.ByteLength));
		SM9Fp.ExportPlain(in value.A0, destination.Slice(SM9Fp.ByteLength));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Norm(in SM9Fp2 value, out SM9Fp result)
	{
		SM9Fp.SquareWide(in value.A0, out SM9FpWide s0);
		SM9Fp.SquareWide(in value.A1, out SM9FpWide s1);
		SM9FpWide.AddTwice(in s0, in s1, out s0);
		SM9Fp.Reduce(in s0, out result);
	}

	// value·(a0 − a1·u)·inverse: −a1 is 3p − a1, below 5.25p, so its product with a reduced inverse is below 11.9p².
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Scale(in SM9Fp2 value, in SM9Fp inverse, out SM9Fp2 result)
	{
		SM9Fp zero = default;
		SM9Fp.SubtractUnreduced(in zero, in value.A1, out SM9Fp negated);
		SM9Fp a0 = value.A0;
		Unsafe.SkipInit(out result);
		SM9Fp.Multiply(in a0, in inverse, out result.A0);
		SM9Fp.Multiply(in negated, in inverse, out result.A1);
		negated.ZeroMemory();
	}
}
