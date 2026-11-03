using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Inversion modulo an odd m of any number of limbs, by the divsteps of SafeGcd: from δ = 1/2, f = m and g = x they bring g to 0 and f to ±gcd(x, m), while d and e, starting at 0 and a numerator N, go through the same linear maps modulo m, so that d·f ends at N/x. The bound of ⌊(45907·log₂M + 26313)/19929⌋ steps holds for 0 ≤ g ≤ f ≤ M at every size, and M = 2^(64·limbs) covers every modulus of that many limbs.
// f, g, d and e are signed values in limbs of 62 bits, the top one a signed long that takes the rest, as in SafeGcd; batches of up to 62 steps run on the bottom limbs and give a matrix that then maps the full values. Neither the time nor the addresses depend on the values, only on the number of limbs.
// The steps and the updates are optimized from their first call, as the kernels are (see IMontgomeryKernel).
internal static class ModularInverse
{
	private const ulong LimbMask = (1UL << 62) - 1;

	// result = numerator/value mod m, below m, for value and numerator below m. A value that shares a factor with m gives a result that is not its inverse, and 0 gives 0.
	internal static void Invert(ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> numerator, ReadOnlySpan<ulong> modulus, Span<ulong> result)
	{
		int limbs = modulus.Length;

		Debug.Assert(value.Length <= limbs && numerator.Length <= limbs && result.Length == limbs && (modulus[0] & 1) is 1);

		int length = 64 * limbs / 62 + 1;
		_ = GetSchedule(limbs, out int batchCount, out int batchSteps);
		int bufferLength = 5 * length;
		using CryptoBuffer<long> buffer = CryptoBuffer<long>.ShouldUsePool(bufferLength) ? new CryptoBuffer<long>(bufferLength) : new CryptoBuffer<long>(stackalloc long[bufferLength]);
		Span<long> f = buffer.Span.Slice(0, length);
		Span<long> g = buffer.Span.Slice(length, length);
		Span<long> d = buffer.Span.Slice(2 * length, length);
		Span<long> e = buffer.Span.Slice(3 * length, length);
		Span<long> m = buffer.Span.Slice(4 * length, length);

		for (int i = 0; i < length; ++i)
		{
			int position = 62 * i;
			long limb = (long)(LimbArithmetic.ReadBits(modulus, position) & LimbMask);
			m[i] = limb;
			f[i] = limb;
			g[i] = (long)(LimbArithmetic.ReadBits(value, position) & LimbMask);
			d[i] = 0;
			e[i] = (long)(LimbArithmetic.ReadBits(numerator, position) & LimbMask);
		}

		ulong inverse = Limbs.InvertWord(modulus[0]);
		// ζ = −(δ + 1/2), for δ starting at 1/2.
		long zeta = -1;

		for (int i = 0; i < batchCount; ++i)
		{
			zeta = Divsteps(zeta, (ulong)f[0], (ulong)g[0], batchSteps, out Transition t);
			UpdateDE(d, e, m, in t, inverse);
			UpdateFG(f, g, in t);
		}

		Store(d, m, f[^1], result);
	}

	// Returns the bound on the steps for moduli of limbs limbs, and batches of equal size, at most 62 steps each, that cover it. No test reaches the inputs that need the most steps, so the batches must cover the bound by construction.
	internal static int GetSchedule(int limbs, out int batchCount, out int batchSteps)
	{
		int stepBound = (int)((45907L * 64 * limbs + 26313) / 19929);
		batchCount = (stepBound + 61) / 62;
		batchSteps = (stepBound + batchCount - 1) / batchCount;
		return stepBound;
	}

	// Runs steps ≤ 62 steps on the low limbs f and g in parts of at most 30, as SafeGcd does, and returns ζ after them, with the matrix scaled by 2^62.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static long Divsteps(long zeta, ulong f, ulong g, int steps, out Transition t)
	{
		int parts = (steps + 29) / 30;
		zeta = PartDivsteps(zeta, ref f, ref g, steps / parts, out ulong uv, out ulong qr);
		Unpack(uv, out long u, out long v);
		Unpack(qr, out long q, out long r);
		zeta = PartDivsteps(zeta, ref f, ref g, (steps + 1) / parts, out uv, out qr);
		Append(uv, qr, ref u, ref v, ref q, ref r);

		if (parts > 2)
		{
			zeta = PartDivsteps(zeta, ref f, ref g, (steps + 2) / parts, out uv, out qr);
			Append(uv, qr, ref u, ref v, ref q, ref r);
		}

		int scale = 62 - steps;
		t = new Transition(u << scale, v << scale, q << scale, r << scale);
		return zeta;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Append(ulong uv, ulong qr, ref long u, ref long v, ref long q, ref long r)
	{
		Unpack(uv, out long nextU, out long nextV);
		Unpack(qr, out long nextQ, out long nextR);
		(u, v, q, r) = (nextU * u + nextV * q, nextU * v + nextV * r, nextQ * u + nextR * q, nextQ * v + nextR * r);
	}

	// The steps of SafeGcd.PartDivsteps, with u·2^32 + v and q·2^32 + r packed in one word each.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static long PartDivsteps(long zeta, ref ulong fValue, ref ulong gValue, int steps, out ulong uvValue, out ulong qrValue)
	{
		ulong f = fValue;
		ulong g = gValue;
		ulong uv = 1UL << 32;
		ulong qr = 1;
		ulong odd = 0 - (g & 1);

		for (int i = 0; i < steps; ++i)
		{
			ulong negate = (ulong)(zeta >> 63);
			ulong swap = negate & odd;
			ulong fNext = f ^ (f ^ g) & swap;
			ulong uvNext = uv ^ (uv ^ qr) & swap;
			g += (f ^ negate) - negate & odd;
			qr += (uv ^ negate) - negate & odd;
			zeta = (zeta ^ (long)swap) - 1;
			f = fNext;
			uv = uvNext << 1;
			odd = (ulong)((long)(g << 62) >> 63);
			g >>= 1;
		}

		fValue = f;
		gValue = g;
		uvValue = uv;
		qrValue = qr;
		return zeta;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Unpack(ulong packed, out long high, out long low)
	{
		low = (int)packed;
		high = (long)(packed - (ulong)low) >> 32;
	}

	// Replaces f and g with t·(f, g)/2^62; the low 62 bits of both sums are zero. The sums stay in locals, which keeps them in registers.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void UpdateFG(Span<long> fLimbs, Span<long> gLimbs, in Transition t)
	{
		ulong u = (ulong)t.U;
		ulong v = (ulong)t.V;
		ulong q = (ulong)t.Q;
		ulong r = (ulong)t.R;
		nint last = fLimbs.Length - 1;
		ref long f = ref MemoryMarshal.GetReference(fLimbs);
		ref long g = ref MemoryMarshal.GetReference(gLimbs);
		ulong f0 = (ulong)f;
		ulong g0 = (ulong)g;
		(ulong Low, ulong High) fSum = ShiftRight62(MultiplyAdd(MultiplyAdd(default, u, f0, 0), v, g0, 0), out _);
		(ulong Low, ulong High) gSum = ShiftRight62(MultiplyAdd(MultiplyAdd(default, q, f0, 0), r, g0, 0), out _);

		for (nint i = 1; i < last; ++i)
		{
			ulong fLimb = (ulong)Unsafe.Add(ref f, i);
			ulong gLimb = (ulong)Unsafe.Add(ref g, i);
			fSum = ShiftRight62(MultiplyAdd(MultiplyAdd(fSum, u, fLimb, 0), v, gLimb, 0), out ulong fBelow);
			gSum = ShiftRight62(MultiplyAdd(MultiplyAdd(gSum, q, fLimb, 0), r, gLimb, 0), out ulong gBelow);
			Unsafe.Add(ref f, i - 1) = (long)fBelow;
			Unsafe.Add(ref g, i - 1) = (long)gBelow;
		}

		ulong fTop = (ulong)Unsafe.Add(ref f, last);
		ulong gTop = (ulong)Unsafe.Add(ref g, last);
		ulong fTopSign = (ulong)((long)fTop >> 63);
		ulong gTopSign = (ulong)((long)gTop >> 63);
		fSum = ShiftRight62(MultiplyAdd(MultiplyAdd(fSum, u, fTop, fTopSign), v, gTop, gTopSign), out ulong fLast);
		gSum = ShiftRight62(MultiplyAdd(MultiplyAdd(gSum, q, fTop, fTopSign), r, gTop, gTopSign), out ulong gLast);
		Unsafe.Add(ref f, last - 1) = (long)fLast;
		Unsafe.Add(ref g, last - 1) = (long)gLast;
		Unsafe.Add(ref f, last) = (long)fSum.Low;
		Unsafe.Add(ref g, last) = (long)gSum.Low;
	}

	// Replaces d and e with t·(d, e)/2^62 modulo m, which keeps them in (−2m, m), as SafeGcd.UpdateDE does.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void UpdateDE(Span<long> dLimbs, Span<long> eLimbs, ReadOnlySpan<long> mLimbs, in Transition t, ulong inverse)
	{
		ulong u = (ulong)t.U;
		ulong v = (ulong)t.V;
		ulong q = (ulong)t.Q;
		ulong r = (ulong)t.R;
		nint last = dLimbs.Length - 1;
		ref long d = ref MemoryMarshal.GetReference(dLimbs);
		ref long e = ref MemoryMarshal.GetReference(eLimbs);
		ref long m = ref MemoryMarshal.GetReference(mLimbs);
		ulong dSign = (ulong)(Unsafe.Add(ref d, last) >> 63);
		ulong eSign = (ulong)(Unsafe.Add(ref e, last) >> 63);
		ulong md = (u & dSign) + (v & eSign);
		ulong me = (q & dSign) + (r & eSign);
		ulong d0 = (ulong)d;
		ulong e0 = (ulong)e;
		(ulong Low, ulong High) dSum = MultiplyAdd(MultiplyAdd(default, u, d0, 0), v, e0, 0);
		(ulong Low, ulong High) eSum = MultiplyAdd(MultiplyAdd(default, q, d0, 0), r, e0, 0);
		md -= inverse * dSum.Low + md & LimbMask;
		me -= inverse * eSum.Low + me & LimbMask;
		ulong m0 = (ulong)m;
		dSum = MultiplyAdd(dSum, md, m0, 0);
		eSum = MultiplyAdd(eSum, me, m0, 0);

		Debug.Assert((dSum.Low & LimbMask) is 0 && (eSum.Low & LimbMask) is 0);

		dSum = ShiftRight62(dSum, out _);
		eSum = ShiftRight62(eSum, out _);

		for (nint i = 1; i < last; ++i)
		{
			ulong dLimb = (ulong)Unsafe.Add(ref d, i);
			ulong eLimb = (ulong)Unsafe.Add(ref e, i);
			ulong mLimb = (ulong)Unsafe.Add(ref m, i);
			dSum = ShiftRight62(MultiplyAdd(MultiplyAdd(MultiplyAdd(dSum, u, dLimb, 0), v, eLimb, 0), md, mLimb, 0), out ulong dBelow);
			eSum = ShiftRight62(MultiplyAdd(MultiplyAdd(MultiplyAdd(eSum, q, dLimb, 0), r, eLimb, 0), me, mLimb, 0), out ulong eBelow);
			Unsafe.Add(ref d, i - 1) = (long)dBelow;
			Unsafe.Add(ref e, i - 1) = (long)eBelow;
		}

		ulong dTop = (ulong)Unsafe.Add(ref d, last);
		ulong eTop = (ulong)Unsafe.Add(ref e, last);
		ulong mTop = (ulong)Unsafe.Add(ref m, last);
		dSum = ShiftRight62(MultiplyAdd(MultiplyAdd(MultiplyAdd(dSum, u, dTop, dSign), v, eTop, eSign), md, mTop, 0), out ulong dLast);
		eSum = ShiftRight62(MultiplyAdd(MultiplyAdd(MultiplyAdd(eSum, q, dTop, dSign), r, eTop, eSign), me, mTop, 0), out ulong eLast);
		Unsafe.Add(ref d, last - 1) = (long)dLast;
		Unsafe.Add(ref e, last - 1) = (long)eLast;
		Unsafe.Add(ref d, last) = (long)dSum.Low;
		Unsafe.Add(ref e, last) = (long)eSum.Low;
	}

	// d is in (−2m, m) and fTop, the top limb of f = ±1, has its sign. Sets result to d·f modulo m, as SafeGcd.Store does.
	private static void Store(Span<long> d, ReadOnlySpan<long> m, long fTop, Span<ulong> result)
	{
		long add = d[^1] >> 63;
		long negate = fTop >> 63;

		for (int i = 0; i < d.Length; ++i)
		{
			d[i] = (d[i] + (m[i] & add) ^ negate) - negate;
		}

		Normalize(d);
		add = d[^1] >> 63;

		for (int i = 0; i < d.Length; ++i)
		{
			d[i] += m[i] & add;
		}

		Normalize(d);

		// Limb j holds bits 64j to 64j + 63, which start at the even bit 64j mod 62 of limb ⌊64j/62⌋ of d, so that two limbs of d cover them.
		for (int j = 0; j < result.Length; ++j)
		{
			int index = 64 * j / 62;
			int shift = 64 * j % 62;
			ulong low = index < d.Length ? (ulong)d[index] : 0;
			ulong high = index + 1 < d.Length ? (ulong)d[index + 1] : 0;
			result[j] = low >> shift | high << 62 - shift;
		}
	}

	// Carries the bits above 62 of every limb but the top one into the next.
	private static void Normalize(Span<long> limbs)
	{
		for (int i = 0; i < limbs.Length - 1; ++i)
		{
			limbs[i + 1] += limbs[i] >> 62;
			limbs[i] &= (long)LimbMask;
		}
	}

	// sum + x·y, for x of either sign and y either below 2^62 or a top limb whose sign mask is ySign, as a signed 128-bit value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong Low, ulong High) MultiplyAdd((ulong Low, ulong High) sum, ulong x, ulong y, ulong ySign)
	{
		ulong productHigh = LimbArithmetic.MultiplyOutOfLine(x, y, out ulong productLow) - (y & (ulong)((long)x >> 63)) - (x & ySign);
		ulong low = sum.Low + productLow;
		return (low, sum.High + productHigh + LimbArithmetic.Carry(low, productLow));
	}

	// sum shifted right by 62 bits, arithmetically, and its low 62 bits in limb.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong Low, ulong High) ShiftRight62((ulong Low, ulong High) sum, out ulong limb)
	{
		limb = sum.Low & LimbMask;
		return (sum.Low >> 62 | sum.High << 2, (ulong)((long)sum.High >> 62));
	}

	private readonly struct Transition(long u, long v, long q, long r)
	{
		internal readonly long U = u;
		internal readonly long V = v;
		internal readonly long Q = q;
		internal readonly long R = r;
	}
}
