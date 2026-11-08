namespace CryptoBase.EllipticCurves.SM9;

// Fp6 = Fp2[v]/(v³ − u), the element C0 + C1·v + C2·v². With v = w² it is the subfield of SM9Fp12 that the conjugation w ↦ −w fixes. Every member takes reduced coefficients and gives reduced ones, or sums of products for one reduction per coefficient, with the bounds of SM9Fp2Wide in multiples of B = (2.25p)². No member branches on or indexes by a value. Any result may be the same variable as an input.
internal struct SM9Fp6
{
	internal SM9Fp2 C0;
	internal SM9Fp2 C1;
	internal SM9Fp2 C2;

	// The product, reduced once per coefficient from MultiplyWide.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Multiply(in SM9Fp6 left, in SM9Fp6 right, out SM9Fp6 result)
	{
		MultiplyWide(in left, in right, out SM9Fp6Wide product);
		SM9Fp6Wide.Reduce(in product, out result);
	}

	// Karatsuba before reduction: with v_i = a_i·b_i, c0 = v0 + u((a1 + a2)(b1 + b2) − v1 − v2), c1 = (a0 + a1)(b0 + b1) − v0 − v1 + u·v2 and c2 = (a0 + a2)(b0 + b2) − v0 − v2 + v1, which are c0 = a0b0 + u(a1b2 + a2b1), c1 = a0b1 + a1b0 + u·a2b2 and c2 = a0b2 + a2b0 + a1b1 as integer polynomials. For reduced inputs, c0 has coefficients in (−10B, B) and (−4B, 4B), c1 in (−8B, 2B) and (−2B, 5B) and c2 in (−6B, 3B) and [0, 6B). The products of the sums, of limbs below 2^53, leave every column below 2^60.6 in magnitude.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void MultiplyWide(in SM9Fp6 left, in SM9Fp6 right, out SM9Fp6Wide result)
	{
		SM9Fp2.MultiplyWide(in left.C0, in right.C0, out SM9Fp2Wide v0);
		SM9Fp2.MultiplyWide(in left.C1, in right.C1, out SM9Fp2Wide v1);
		SM9Fp2.MultiplyWide(in left.C2, in right.C2, out SM9Fp2Wide v2);
		SM9Fp2.AddUnreduced(in left.C1, in left.C2, out SM9Fp2 l);
		SM9Fp2.AddUnreduced(in right.C1, in right.C2, out SM9Fp2 r);
		SM9Fp2.MultiplyWide(in l, in r, out SM9Fp2Wide t);
		SM9Fp2Wide.Subtract(in t, in v1, out t);
		SM9Fp2Wide.Subtract(in t, in v2, out t);
		SM9Fp2Wide.AddTimesU(in v0, in t, out result.C0);
		SM9Fp2.AddUnreduced(in left.C0, in left.C1, out l);
		SM9Fp2.AddUnreduced(in right.C0, in right.C1, out r);
		SM9Fp2.MultiplyWide(in l, in r, out t);
		SM9Fp2Wide.Subtract(in t, in v0, out t);
		SM9Fp2Wide.Subtract(in t, in v1, out t);
		SM9Fp2Wide.AddTimesU(in t, in v2, out result.C1);
		SM9Fp2.AddUnreduced(in left.C0, in left.C2, out l);
		SM9Fp2.AddUnreduced(in right.C0, in right.C2, out r);
		SM9Fp2.MultiplyWide(in l, in r, out t);
		SM9Fp2Wide.Subtract(in t, in v0, out t);
		SM9Fp2Wide.Subtract(in t, in v2, out t);
		SM9Fp2Wide.Add(in t, in v1, out result.C2);
	}

	// Chung and Hasan's SQR2: with s0 = a0², s1 = 2a0a1, s2 = (a0 − a1 + a2)², s3 = 2a1a2 and s4 = a2², c0 = s0 + u·s3, c1 = s1 + u·s4 and c2 = s1 + s2 + s3 − s0 − s4.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Square(in SM9Fp6 value, out SM9Fp6 result)
	{
		SM9Fp2.Square(in value.C0, out SM9Fp2 s0);
		SM9Fp2.Multiply(in value.C0, in value.C1, out SM9Fp2 s1);
		SM9Fp2.Double(in s1, out s1);
		SM9Fp2.Subtract(in value.C0, in value.C1, out SM9Fp2 s2);
		SM9Fp2.Add(in s2, in value.C2, out s2);
		SM9Fp2.Square(in s2, out s2);
		SM9Fp2.Multiply(in value.C1, in value.C2, out SM9Fp2 s3);
		SM9Fp2.Double(in s3, out s3);
		SM9Fp2.Square(in value.C2, out SM9Fp2 s4);
		Unsafe.SkipInit(out result);
		SM9Fp2.MultiplyByU(in s3, out SM9Fp2 t);
		SM9Fp2.Add(in s0, in t, out result.C0);
		SM9Fp2.Add(in s1, in s2, out s2);
		SM9Fp2.Add(in s2, in s3, out s2);
		SM9Fp2.Subtract(in s2, in s0, out s2);
		SM9Fp2.Subtract(in s2, in s4, out result.C2);
		SM9Fp2.MultiplyByU(in s4, out t);
		SM9Fp2.Add(in s1, in t, out result.C1);
	}

	// value·(x0 + x1·v) before reduction, the shape of the first half of a line: a0x0 + u·a2x1, (a0 + a1)(x0 + x1) − a0x0 − a1x1 and a1x1 + a2x0, five products. For reduced inputs the first has coefficients in (−6B, B) and (−2B, 3B) and the others, sums of two products, in (−4B, 2B) and [0, 4B); every column is below 2^59.6 in magnitude.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void MultiplyBy01Wide(in SM9Fp6 value, in SM9Fp2 x0, in SM9Fp2 x1, out SM9Fp6Wide result)
	{
		SM9Fp2.MultiplyWide(in value.C0, in x0, out SM9Fp2Wide t0);
		SM9Fp2.MultiplyWide(in value.C1, in x1, out SM9Fp2Wide t1);
		SM9Fp2.MultiplyWide(in value.C2, in x1, out SM9Fp2Wide t2);
		SM9Fp2.MultiplyWide(in value.C2, in x0, out SM9Fp2Wide t3);
		SM9Fp2.AddUnreduced(in value.C0, in value.C1, out SM9Fp2 l);
		SM9Fp2.AddUnreduced(in x0, in x1, out SM9Fp2 r);
		SM9Fp2.MultiplyWide(in l, in r, out SM9Fp2Wide s);
		SM9Fp2Wide.Subtract(in s, in t0, out s);
		SM9Fp2Wide.Subtract(in s, in t1, out result.C1);
		SM9Fp2Wide.Add(in t1, in t3, out result.C2);
		SM9Fp2Wide.AddTimesU(in t0, in t2, out result.C0);
	}

	// value·x·v before reduction = u·a2x + a0x·v + a1x·v², the shape of the second half of a line; for reduced inputs the first coefficient lies in (−4B, 0] and (−2B, B) and the others are single products.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void MultiplyBy1Wide(in SM9Fp6 value, in SM9Fp2 x, out SM9Fp6Wide result)
	{
		SM9Fp2.MultiplyWide(in value.C0, in x, out result.C1);
		SM9Fp2.MultiplyWide(in value.C1, in x, out result.C2);
		SM9Fp2.MultiplyWide(in value.C2, in x, out SM9Fp2Wide t);
		SM9Fp2Wide zero = default;
		SM9Fp2Wide.AddTimesU(in zero, in t, out result.C0);
	}

	// value·v = u·a2 + a0·v + a1·v².
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyByV(in SM9Fp6 value, out SM9Fp6 result)
	{
		SM9Fp2 c0 = value.C0;
		SM9Fp2 c1 = value.C1;
		Unsafe.SkipInit(out result);
		SM9Fp2.MultiplyByU(in value.C2, out result.C0);
		result.C1 = c0;
		result.C2 = c1;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Add(in SM9Fp6 left, in SM9Fp6 right, out SM9Fp6 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.Add(in left.C0, in right.C0, out result.C0);
		SM9Fp2.Add(in left.C1, in right.C1, out result.C1);
		SM9Fp2.Add(in left.C2, in right.C2, out result.C2);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Subtract(in SM9Fp6 left, in SM9Fp6 right, out SM9Fp6 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.Subtract(in left.C0, in right.C0, out result.C0);
		SM9Fp2.Subtract(in left.C1, in right.C1, out result.C1);
		SM9Fp2.Subtract(in left.C2, in right.C2, out result.C2);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Negate(in SM9Fp6 value, out SM9Fp6 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.Negate(in value.C0, out result.C0);
		SM9Fp2.Negate(in value.C1, out result.C1);
		SM9Fp2.Negate(in value.C2, out result.C2);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Double(in SM9Fp6 value, out SM9Fp6 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.Double(in value.C0, out result.C0);
		SM9Fp2.Double(in value.C1, out result.C1);
		SM9Fp2.Double(in value.C2, out result.C2);
	}

	[SkipLocalsInit]
	internal static void ConditionalSelect(ulong mask, in SM9Fp6 whenSet, in SM9Fp6 whenClear, out SM9Fp6 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.ConditionalSelect(mask, in whenSet.C0, in whenClear.C0, out result.C0);
		SM9Fp2.ConditionalSelect(mask, in whenSet.C1, in whenClear.C1, out result.C1);
		SM9Fp2.ConditionalSelect(mask, in whenSet.C2, in whenClear.C2, out result.C2);
	}

	// With t0 = a0² − u·a1a2, t1 = u·a2² − a0a1 and t2 = a1² − a0a2, value·(t0 + t1·v + t2·v²) is the norm a0t0 + u(a2t1 + a1t2) in Fp2. 0 gives 0; the inversion takes constant time.
	[SkipLocalsInit]
	internal static void Invert(in SM9Fp6 value, out SM9Fp6 result)
	{
		SM9Fp2.Square(in value.C0, out SM9Fp2 t0);
		SM9Fp2.Multiply(in value.C1, in value.C2, out SM9Fp2 t);
		SM9Fp2.MultiplyByU(in t, out t);
		SM9Fp2.Subtract(in t0, in t, out t0);
		SM9Fp2.Square(in value.C2, out SM9Fp2 t1);
		SM9Fp2.MultiplyByU(in t1, out t1);
		SM9Fp2.Multiply(in value.C0, in value.C1, out t);
		SM9Fp2.Subtract(in t1, in t, out t1);
		SM9Fp2.Square(in value.C1, out SM9Fp2 t2);
		SM9Fp2.Multiply(in value.C0, in value.C2, out t);
		SM9Fp2.Subtract(in t2, in t, out t2);
		SM9Fp2.Multiply(in value.C2, in t1, out SM9Fp2 norm);
		SM9Fp2.Multiply(in value.C1, in t2, out t);
		SM9Fp2.Add(in norm, in t, out norm);
		SM9Fp2.MultiplyByU(in norm, out norm);
		SM9Fp2.Multiply(in value.C0, in t0, out t);
		SM9Fp2.Add(in norm, in t, out norm);
		SM9Fp2.Invert(in norm, out norm);
		Unsafe.SkipInit(out result);
		SM9Fp2.Multiply(in t0, in norm, out result.C0);
		SM9Fp2.Multiply(in t1, in norm, out result.C1);
		SM9Fp2.Multiply(in t2, in norm, out result.C2);
		t0.ZeroMemory();
		t1.ZeroMemory();
		t2.ZeroMemory();
		t.ZeroMemory();
		norm.ZeroMemory();
	}
}
