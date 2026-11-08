namespace CryptoBase.EllipticCurves.SM9;

// Fp12 = Fp6[w]/(w² − v), the element C0 + C1·w. In the basis of the powers of w, w⁶ = u, its coefficients over Fp2 are C0.C0, C1.C0, C0.C1, C1.C1, C0.C2 and C1.C2 for w⁰ to w⁵. GM/T 0044.5 §3.2 builds the same field as Fp4 = Fp2[V]/(V² − u) and Fp12 = Fp4[w]/(w³ − V), so V = w³, and writes f = a·w² + b·w + c with a = a1·V + a0, b = b1·V + b0 and c = c1·V + c0: a1, a0, b1, b0, c1 and c0, in the order of its encoding, are the coefficients of w⁵, w², w⁴, w¹, w³ and w⁰.
// Every member takes and gives reduced coefficients. No member branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal struct SM9Fp12
{
	internal SM9Fp6 C0;
	internal SM9Fp6 C1;

	internal const int ByteLength = 12 * SM9Fp.ByteLength;

	// Karatsuba over Fp6 with one reduction per coefficient: with t0 = a0·b0 and t1 = a1·b1, c0 = t0 + v·t1 and c1 = (a0 + a1)(b0 + b1) − t0 − t1 = a0b1 + a1b0. From the bounds of SM9Fp6.MultiplyWide, the coefficients of c0 lie in (−22B, 11B), and those of c1, whose first product takes the reduced sums rather than the sums themselves, in (−12B, 21B), within those of SM9Fp.ReduceWide, 128p² > 25B and 342p² > 67B. The three products are normalized first, so that their combinations keep small columns.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Multiply(in SM9Fp12 left, in SM9Fp12 right, out SM9Fp12 result)
	{
		SM9Fp6.MultiplyWide(in left.C0, in right.C0, out SM9Fp6Wide t0);
		SM9Fp6.MultiplyWide(in left.C1, in right.C1, out SM9Fp6Wide t1);
		SM9Fp6.Add(in left.C0, in left.C1, out SM9Fp6 l);
		SM9Fp6.Add(in right.C0, in right.C1, out SM9Fp6 r);
		SM9Fp6.MultiplyWide(in l, in r, out SM9Fp6Wide m);
		SM9Fp6Wide.Normalize(ref t0);
		SM9Fp6Wide.Normalize(ref t1);
		SM9Fp6Wide.Normalize(ref m);
		SM9Fp6Wide.Subtract(in m, in t0, out m);
		SM9Fp6Wide.Subtract(in m, in t1, out m);
		SM9Fp6Wide.AddTimesV(in t0, in t1, out t0);
		Unsafe.SkipInit(out result);
		SM9Fp6Wide.Reduce(in t0, out result.C0);
		SM9Fp6Wide.Reduce(in m, out result.C1);
	}

	// With t = a0·a1, c0 = (a0 + a1)(a0 + v·a1) − t − v·t = a0² + v·a1² and c1 = 2t. Combining the reduced products costs no more than combining them unreduced, which needs normalized columns, and saves no reduction.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Square(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9Fp6.Multiply(in value.C0, in value.C1, out SM9Fp6 t);
		SM9Fp6.Add(in value.C0, in value.C1, out SM9Fp6 l);
		SM9Fp6.MultiplyByV(in value.C1, out SM9Fp6 r);
		SM9Fp6.Add(in value.C0, in r, out r);
		SM9Fp6.Multiply(in l, in r, out l);
		Unsafe.SkipInit(out result);
		SM9Fp6.Subtract(in l, in t, out l);
		SM9Fp6.MultiplyByV(in t, out r);
		SM9Fp6.Subtract(in l, in r, out result.C0);
		SM9Fp6.Double(in t, out result.C1);
	}

	// The square of an element of the cyclotomic subgroup, of order p⁴ − p² + 1, which holds GT (Granger and Scott, "Faster squaring in the cyclotomic subgroup of sixth degree extensions", 2010). Over Fp4 = Fp2[V], V = w³, the element is c + b·w + a·w² with c = (w⁰, w³), b = (w¹, w⁴) and a = (w², w⁵), and its square is (3c² − 2c̄) + (3V·a² + 2b̄)·w + (3b² − 2ā)·w², where x̄ = x0 − x1·V. Each square of Fp4 is (x0² + u·x1², 2x0x1), three squares of Fp2. Other elements give wrong results.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void CyclotomicSquare(in SM9Fp12 value, out SM9Fp12 result)
	{
		SquareFp4(in value.C0.C0, in value.C1.C1, out SM9Fp2 c0, out SM9Fp2 c1);
		SquareFp4(in value.C1.C0, in value.C0.C2, out SM9Fp2 a0, out SM9Fp2 a1);
		SquareFp4(in value.C0.C1, in value.C1.C2, out SM9Fp2 b1, out SM9Fp2 t);
		SM9Fp2.MultiplyByU(in t, out SM9Fp2 b0);
		Unsafe.SkipInit(out SM9Fp12 square);
		TripleMinusTwice(in c0, in value.C0.C0, out square.C0.C0);
		TriplePlusTwice(in c1, in value.C1.C1, out square.C1.C1);
		TripleMinusTwice(in a0, in value.C0.C1, out square.C0.C1);
		TriplePlusTwice(in a1, in value.C1.C2, out square.C1.C2);
		TriplePlusTwice(in b0, in value.C1.C0, out square.C1.C0);
		TripleMinusTwice(in b1, in value.C0.C2, out square.C0.C2);
		result = square;
	}

	// value·l for a line l = l0 + l2·w² + l3·w³ = (l0 + l2·v) + l3·v·w, by Karatsuba over Fp6 with one reduction per coefficient: with A = f0·(l0 + l2·v) and B = f1·l3·v, c0 = A + v·B and c1 = (f0 + f1)(l0 + (l2 + l3)·v) − A − B, thirteen products of Fp2. With f0 + f1 and l2 + l3 reduced, the coefficients of c0 lie in (−10B, 6B) and those of c1 in (−7B, 11B) for reduced inputs, and the columns, each a sum of at most three of MultiplyBy01Wide, stay below 2^61.2 in magnitude.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void MultiplyByLine(in SM9Fp12 value, in SM9Fp2 l0, in SM9Fp2 l2, in SM9Fp2 l3, out SM9Fp12 result)
	{
		SM9Fp6.MultiplyBy01Wide(in value.C0, in l0, in l2, out SM9Fp6Wide a);
		SM9Fp6.MultiplyBy1Wide(in value.C1, in l3, out SM9Fp6Wide b);
		SM9Fp6.Add(in value.C0, in value.C1, out SM9Fp6 s);
		SM9Fp2.Add(in l2, in l3, out SM9Fp2 x1);
		SM9Fp6.MultiplyBy01Wide(in s, in l0, in x1, out SM9Fp6Wide c);
		SM9Fp6Wide.Subtract(in c, in a, out c);
		SM9Fp6Wide.Subtract(in c, in b, out c);
		SM9Fp6Wide.AddTimesV(in a, in b, out a);
		Unsafe.SkipInit(out result);
		SM9Fp6Wide.Reduce(in a, out result.C0);
		SM9Fp6Wide.Reduce(in c, out result.C1);
	}

	// value·(l0 + l2·w² + w³), the form of a line of SM9PrecomputedLine at P: with value = g + h·w and L = l0 + l2·v, as w³ = v·w, it is (g·L + v²·h) + (v·g + h·L)·w, ten products of Fp2 by SM9Fp6.MultiplyBy01Wide, while v·g = (u·g2, g0, g1) and v²·h = (u·h1, u·h2, h0) take no product: they go into the sums before the reduction as values times R, each reduced once with them. For reduced inputs, a coefficient with a term u·x then lies in (−30.4p², 145p²) and (−10.2p², 71p²), and one with a term x in (−20.3p², 60.8p²) and [0, 71p²), within those of SM9Fp.ReduceWide, and the columns stay below 2^59.7 in magnitude.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void MultiplyByNormalizedLine(in SM9Fp12 value, in SM9Fp2 l0, in SM9Fp2 l2, out SM9Fp12 result)
	{
		SM9Fp6.MultiplyBy01Wide(in value.C0, in l0, in l2, out SM9Fp6Wide a);
		SM9Fp6.MultiplyBy01Wide(in value.C1, in l0, in l2, out SM9Fp6Wide b);
		SM9Fp2Wide.AddShiftedTimesU(ref a.C0, in value.C1.C1);
		SM9Fp2Wide.AddShiftedTimesU(ref a.C1, in value.C1.C2);
		SM9Fp2Wide.AddShifted(ref a.C2, in value.C1.C0);
		SM9Fp2Wide.AddShiftedTimesU(ref b.C0, in value.C0.C2);
		SM9Fp2Wide.AddShifted(ref b.C1, in value.C0.C0);
		SM9Fp2Wide.AddShifted(ref b.C2, in value.C0.C1);
		Unsafe.SkipInit(out result);
		SM9Fp6Wide.Reduce(in a, out result.C0);
		SM9Fp6Wide.Reduce(in b, out result.C1);
	}

	// value^(p⁶) = C0 − C1·w, the inverse of an element of the cyclotomic subgroup.
	[SkipLocalsInit]
	internal static void Conjugate(in SM9Fp12 value, out SM9Fp12 result)
	{
		Unsafe.SkipInit(out result);
		result.C0 = value.C0;
		SM9Fp6.Negate(in value.C1, out result.C1);
	}

	// value^p: the coefficient f_i of w^i goes to f̄_i·γ_i with γ_i = w^(i(p − 1)) = u^(i(p − 1)/6), which lies in Fp.
	[SkipLocalsInit]
	internal static void Frobenius(in SM9Fp12 value, out SM9Fp12 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.Conjugate(in value.C0.C0, out result.C0.C0);
		ConjugateScale(in value.C1.C0, Frobenius1Limbs1, out result.C1.C0);
		ConjugateScale(in value.C0.C1, Frobenius1Limbs2, out result.C0.C1);
		ConjugateScale(in value.C1.C1, Frobenius1Limbs3, out result.C1.C1);
		ConjugateScale(in value.C0.C2, Frobenius1Limbs4, out result.C0.C2);
		ConjugateScale(in value.C1.C2, Frobenius1Limbs5, out result.C1.C2);
	}

	// value^(p²): f_i goes to f_i·w^(i(p² − 1)), as the p²-power Frobenius fixes Fp2; γ_3 is −1.
	[SkipLocalsInit]
	internal static void FrobeniusSquared(in SM9Fp12 value, out SM9Fp12 result)
	{
		Unsafe.SkipInit(out result);
		result.C0.C0 = value.C0.C0;
		SM9Fp2.MultiplyByFp(in value.C1.C0, in SM9Fp.FromConstant(Frobenius2Limbs1), out result.C1.C0);
		SM9Fp2.MultiplyByFp(in value.C0.C1, in SM9Fp.FromConstant(Frobenius2Limbs2), out result.C0.C1);
		SM9Fp2.Negate(in value.C1.C1, out result.C1.C1);
		SM9Fp2.MultiplyByFp(in value.C0.C2, in SM9Fp.FromConstant(Frobenius2Limbs4), out result.C0.C2);
		SM9Fp2.MultiplyByFp(in value.C1.C2, in SM9Fp.FromConstant(Frobenius2Limbs5), out result.C1.C2);
	}

	// value^(p³): f_i goes to f̄_i·w^(i(p³ − 1)); γ_2 is −1 and γ_4 is 1.
	[SkipLocalsInit]
	internal static void FrobeniusCubed(in SM9Fp12 value, out SM9Fp12 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp2.Conjugate(in value.C0.C0, out result.C0.C0);
		ConjugateScale(in value.C1.C0, Frobenius3Limbs1, out result.C1.C0);
		SM9Fp2.Conjugate(in value.C0.C1, out SM9Fp2 t);
		SM9Fp2.Negate(in t, out result.C0.C1);
		ConjugateScale(in value.C1.C1, Frobenius3Limbs3, out result.C1.C1);
		SM9Fp2.Conjugate(in value.C0.C2, out result.C0.C2);
		ConjugateScale(in value.C1.C2, Frobenius3Limbs5, out result.C1.C2);
	}

	// (C0 − C1·w)/(C0² − v·C1²). 0 gives 0; the inversion takes constant time, and the intermediates are erased.
	[SkipLocalsInit]
	internal static void Invert(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9Fp6.Square(in value.C0, out SM9Fp6 t0);
		SM9Fp6.Square(in value.C1, out SM9Fp6 t1);
		SM9Fp6.MultiplyByV(in t1, out t1);
		SM9Fp6.Subtract(in t0, in t1, out t0);
		SM9Fp6.Invert(in t0, out t0);
		Unsafe.SkipInit(out result);
		SM9Fp6.Multiply(in value.C1, in t0, out t1);
		SM9Fp6.Multiply(in value.C0, in t0, out result.C0);
		SM9Fp6.Negate(in t1, out result.C1);
		t0.ZeroMemory();
		t1.ZeroMemory();
	}

	[SkipLocalsInit]
	internal static ulong AreEqual(in SM9Fp12 left, in SM9Fp12 right)
	{
		ulong equal = SM9Fp2.AreEqual(in left.C0.C0, in right.C0.C0) & SM9Fp2.AreEqual(in left.C0.C1, in right.C0.C1) & SM9Fp2.AreEqual(in left.C0.C2, in right.C0.C2);
		return equal & SM9Fp2.AreEqual(in left.C1.C0, in right.C1.C0) & SM9Fp2.AreEqual(in left.C1.C1, in right.C1.C1) & SM9Fp2.AreEqual(in left.C1.C2, in right.C1.C2);
	}

	[SkipLocalsInit]
	internal static void ConditionalSelect(ulong mask, in SM9Fp12 whenSet, in SM9Fp12 whenClear, out SM9Fp12 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp6.ConditionalSelect(mask, in whenSet.C0, in whenClear.C0, out result.C0);
		SM9Fp6.ConditionalSelect(mask, in whenSet.C1, in whenClear.C1, out result.C1);
	}

	// Writes the 384 bytes of GM/T 0044.1 §7.2.6 for value, high dimension first as GM/T 0044.5 §3.2 lists them: the plain coefficients of w⁵, w², w⁴, w¹, w³ and w⁰, each u-coefficient first.
	[SkipLocalsInit]
	internal static void Encode(in SM9Fp12 value, Span<byte> destination)
	{
		Debug.Assert(destination.Length is ByteLength);

		SM9Fp2.ExportPlain(in value.C1.C2, destination.Slice(0, SM9Fp2.ByteLength));
		SM9Fp2.ExportPlain(in value.C0.C1, destination.Slice(SM9Fp2.ByteLength, SM9Fp2.ByteLength));
		SM9Fp2.ExportPlain(in value.C0.C2, destination.Slice(2 * SM9Fp2.ByteLength, SM9Fp2.ByteLength));
		SM9Fp2.ExportPlain(in value.C1.C0, destination.Slice(3 * SM9Fp2.ByteLength, SM9Fp2.ByteLength));
		SM9Fp2.ExportPlain(in value.C1.C1, destination.Slice(4 * SM9Fp2.ByteLength, SM9Fp2.ByteLength));
		SM9Fp2.ExportPlain(in value.C0.C0, destination.Slice(5 * SM9Fp2.ByteLength, SM9Fp2.ByteLength));
	}

	// (x0 + x1·V)² = (x0² + u·x1², (x0 + x1)² − x0² − x1²), reduced once per coefficient. For reduced inputs x0² + u·x1² has coefficients in (−6B, B) and (−2B, 3B) and 2x0x1 in (−4B, 2B) and [0, 4B); the columns stay below 2^59.4 in magnitude.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	private static void SquareFp4(in SM9Fp2 x0, in SM9Fp2 x1, out SM9Fp2 s0, out SM9Fp2 s1)
	{
		SM9Fp2.SquareWide(in x0, out SM9Fp2Wide t0);
		SM9Fp2.SquareWide(in x1, out SM9Fp2Wide t1);
		SM9Fp2.AddUnreduced(in x0, in x1, out SM9Fp2 sum);
		SM9Fp2.SquareWide(in sum, out SM9Fp2Wide t2);
		SM9Fp2Wide.Subtract(in t2, in t0, out t2);
		SM9Fp2Wide.Subtract(in t2, in t1, out t2);
		SM9Fp2Wide.AddTimesU(in t0, in t1, out t0);
		SM9Fp2Wide.Reduce(in t0, out s0);
		SM9Fp2Wide.Reduce(in t2, out s1);
	}

	// 3x − 2y as 3x + 2(3p − y), below 12.75p, reduced.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void TripleMinusTwice(in SM9Fp2 x, in SM9Fp2 y, out SM9Fp2 result)
	{
		SM9Fp zero = default;
		SM9Fp.SubtractUnreduced(in zero, in y.A0, out SM9Fp n0);
		SM9Fp.SubtractUnreduced(in zero, in y.A1, out SM9Fp n1);
		Unsafe.SkipInit(out result);
		Combine(in x.A0, in n0, out result.A0);
		Combine(in x.A1, in n1, out result.A1);
	}

	// 3x + 2y, below 11.25p, reduced.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void TriplePlusTwice(in SM9Fp2 x, in SM9Fp2 y, out SM9Fp2 result)
	{
		SM9Fp2 yCopy = y;
		Unsafe.SkipInit(out result);
		Combine(in x.A0, in yCopy.A0, out result.A0);
		Combine(in x.A1, in yCopy.A1, out result.A1);
	}

	// 3x + 2y for limbs of x below 2^52 and of y below 2^53 and a value below 2^260.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Combine(in SM9Fp x, in SM9Fp y, out SM9Fp result)
	{
		Unsafe.SkipInit(out result);
		result.L0 = 3 * x.L0 + 2 * y.L0;
		result.L1 = 3 * x.L1 + 2 * y.L1;
		result.L2 = 3 * x.L2 + 2 * y.L2;
		result.L3 = 3 * x.L3 + 2 * y.L3;
		result.L4 = 3 * x.L4 + 2 * y.L4;
		SM9Fp.WeakReduce(in result, out result);
	}

	// x̄·γ for γ in Fp.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ConjugateScale(in SM9Fp2 value, ReadOnlySpan<ulong> gamma, out SM9Fp2 result)
	{
		SM9Fp2.Conjugate(in value, out SM9Fp2 conjugate);
		SM9Fp2.MultiplyByFp(in conjugate, in SM9Fp.FromConstant(gamma), out result);
	}

	// w^(i(p − 1)) in Montgomery form, for i from 1 to 5.
	private static ReadOnlySpan<ulong> Frobenius1Limbs1 => [0x00031ACDCC321297, 0x000E1ED872EA702E, 0x0005B828473333CC, 0x000BEF773C637B1C, 0x0000AE34015D37C6];

	private static ReadOnlySpan<ulong> Frobenius1Limbs2 => [0x0002618D1DD0E1A6, 0x000BF49DA3AB3978, 0x000DF784163EB18C, 0x0004B461AFE848FE, 0x00005AD3E7485AD5];

	private static ReadOnlySpan<ulong> Frobenius1Limbs3 => [0x00040FED6351CB37, 0x000802D4456F8F4A, 0x000288FFBAF6F244, 0x0003113A724F7F5D, 0x0000434EEC25273D];

	private static ReadOnlySpan<ulong> Frobenius1Limbs4 => [0x0009B6FAA6CCDA64, 0x00033906AC1994F1, 0x00083CA407298A35, 0x000A40E7F4F3D6F0, 0x00000453E74894E5];

	private static ReadOnlySpan<ulong> Frobenius1Limbs5 => [0x000090477A70FE1D, 0x000E95A38172DD73, 0x00025F9EB8E5B10A, 0x000190E09626B940, 0x00004B5AEAC7F21A];

	// w^(i(p² − 1)) for i = 1, 2, 4 and 5.
	private static ReadOnlySpan<ulong> Frobenius2Limbs1 => [0x0002618D1DD0E1A6, 0x000BF49DA3AB3978, 0x000DF784163EB18C, 0x0004B461AFE848FE, 0x00005AD3E7485AD5];

	private static ReadOnlySpan<ulong> Frobenius2Limbs2 => [0x0009B6FAA6CCDA64, 0x00033906AC1994F1, 0x00083CA407298A35, 0x000A40E7F4F3D6F0, 0x00000453E74894E5];

	private static ReadOnlySpan<ulong> Frobenius2Limbs4 => [0x000D399AC58063D7, 0x0008BD0A0B4284DE, 0x000797432EE34106, 0x0005BABBB0526C00, 0x00005B6C18B7A7CE];

	private static ReadOnlySpan<ulong> Frobenius2Limbs5 => [0x0005E42D3C846B19, 0x000178A102D42965, 0x000D52233DF8685E, 0x00002E356B46DE0E, 0x0000B1EC18B76DBE];

	// w^(i(p³ − 1)) for i = 1, 3 and 5.
	private static ReadOnlySpan<ulong> Frobenius3Limbs1 => [0x00040FED6351CB37, 0x000802D4456F8F4A, 0x000288FFBAF6F244, 0x0003113A724F7F5D, 0x0000434EEC25273D];

	private static ReadOnlySpan<ulong> Frobenius3Limbs3 => [0x000B8B3A7FFF7A46, 0x000CAED3697E2F0C, 0x000305C78A2B004E, 0x00075DE2EDEB35A2, 0x000072F113DADB66];

	private static ReadOnlySpan<ulong> Frobenius3Limbs5 => [0x00040FED6351CB37, 0x000802D4456F8F4A, 0x000288FFBAF6F244, 0x0003113A724F7F5D, 0x0000434EEC25273D];
}
