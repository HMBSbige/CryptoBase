using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// Inversion modulo m by divsteps, which take (δ, f, g) with f odd to (1 − δ, g, (g − f)/2) if δ > 0 and g is odd, to (1 + δ, f, (g + f)/2) if only g is odd and to (1 + δ, f, g/2) if g is even. They keep gcd(f, g), and from f = m and g = x they bring g to 0 and f to ±gcd(x, m) = ±1. d and e start at 0 and R² and go through the same linear maps modulo m, so d ≡ f·R²/x and e ≡ g·R²/x throughout and d·f ends at R²/x, which for x = aR is a⁻¹R; x = 0 leaves d at 0.
// e may start at any N below m in place of R², which ends d·f at N/x.
// f, g, d and e are signed values in Length limbs of 62 bits, least significant first, the last limb a signed long that takes the rest. The steps read only δ and the low bits of f and g, so a batch of up to 62 runs on the bottom limbs alone and yields a matrix, scaled by 2^62, that then maps the full values at once. The division by 2^62 is exact for f and g; d and e first gain the multiple of m that clears their low 62 bits, which keeps them in (−2m, m).
internal static class SafeGcd<TModulus> where TModulus : struct, IMontgomeryModulus
{
	private const ulong LimbMask = (1UL << 62) - 1;

	// 576 bits, the most that MaxLimbCount limbs hold, need 10 limbs.
	private const int Capacity = 10;

	// 62·Length exceeds BitLength, so that the top limb of a value in (−2m, m) is below 2^62 in magnitude. Without tiered compilation the JIT does not inline these properties unless told to, and a loop would call them on every turn.
	private static int Length
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TModulus.BitLength / 62 + 1;
	}

	// From δ = 1/2, the divsteps bring g to 0 within ⌊(45907·log₂M + 26313)/19929⌋ steps for 0 ≤ g ≤ f ≤ M; f = m and M = 2^BitLength give 591, 885 and 1201 steps for 256, 384 and 521 bits. No test reaches the inputs that need the most steps, so the batches below must cover this bound by construction.
	internal static int StepBound
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => (45907 * TModulus.BitLength + 26313) / 19929;
	}

	// The matrix of a batch holds entries up to 2^62, so a batch runs at most 62 steps.
	internal static int BatchCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => (StepBound + 61) / 62;
	}

	// Batches of equal size that cover StepBound: 60, 59 and 61 steps for 256, 384 and 521 bits.
	internal static int BatchSteps
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => (StepBound + BatchCount - 1) / BatchCount;
	}

	// Neither the time nor the addresses depend on value: BatchCount batches of BatchSteps steps cover the bound for any value, and every step and update works with masks.
	internal static void Invert(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		Invert(in value, TModulus.RSquared, out result);
	}

	// As above, but giving numerator/value mod m in place of R²/value, for a numerator below m. Not inlined, nor is Load: with the loop inlined into a caller, or Load into the loop, the inlining budget runs out before the helpers of the matrix updates, which then become calls in every batch.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void Invert(in FieldElement<TModulus> value, ReadOnlySpan<ulong> numerator, out FieldElement<TModulus> result)
	{
		Load(in value, numerator, out State state);
		// ζ = −(δ + 1/2), for δ starting at 1/2.
		long zeta = -1;

		for (int i = 0; i < BatchCount; ++i)
		{
			zeta = Divsteps(zeta, (ulong)state.F[0], (ulong)state.G[0], out Transition t);
			UpdateDE(ref state, in t);
			UpdateFG(ref state.F[0], ref state.G[0], in t, Length);
		}

		Store(ref state, state.F[Length - 1], out result);
		state.ZeroMemory();
	}

	// The time depends on value, which must be public. The loop ends once g is 0, and f and g lose their top limbs as they shrink.
	internal static void InvertVariableTime(in FieldElement<TModulus> value, out FieldElement<TModulus> result)
	{
		InvertVariableTime(in value, TModulus.RSquared, out result);
	}

	// As above, but giving numerator/value mod m in place of R²/value, for a numerator below m. Not inlined, for the reason given at Invert.
	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	internal static void InvertVariableTime(in FieldElement<TModulus> value, ReadOnlySpan<ulong> numerator, out FieldElement<TModulus> result)
	{
		Load(in value, numerator, out State state);
		ref long f = ref state.F[0];
		ref long g = ref state.G[0];
		// η = −δ, for δ starting at 1.
		long eta = -1;
		int length = Length;

		while (true)
		{
			eta = DivstepsVariableTime(eta, (ulong)f, (ulong)g, out Transition t);
			UpdateDE(ref state, in t);
			UpdateFG(ref f, ref g, in t, length);

			if (IsZero(ref g, length))
			{
				break;
			}

			long fTop = Unsafe.Add(ref f, length - 1);
			long gTop = Unsafe.Add(ref g, length - 1);

			// Top limbs that are only the sign of the limbs below them fold into those.
			if (length > 1 && (fTop ^ fTop >> 63 | gTop ^ gTop >> 63) is 0)
			{
				Unsafe.Add(ref f, length - 2) |= fTop << 62;
				Unsafe.Add(ref g, length - 2) |= gTop << 62;
				--length;
			}
		}

		Store(ref state, Unsafe.Add(ref f, length - 1), out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Load(in FieldElement<TModulus> value, ReadOnlySpan<ulong> numerator, out State state)
	{
		Debug.Assert(Length <= Capacity && numerator.Length == TModulus.LimbCount);

		Unsafe.SkipInit(out state);
		ReadOnlySpan<ulong> modulus = TModulus.Modulus;
		ReadOnlySpan<ulong> x = FieldElement<TModulus>.GetLimbs(in value);

		for (int i = 0; i < Length; ++i)
		{
			int position = 62 * i;
			long limb = (long)(ReadBits(modulus, position) & LimbMask);
			state.M[i] = limb;
			state.F[i] = limb;
			state.G[i] = (long)(ReadBits(x, position) & LimbMask);
			state.D[i] = 0;
			state.E[i] = (long)(ReadBits(numerator, position) & LimbMask);
		}
	}

	// Runs BatchSteps steps on the low limbs f and g and returns ζ after them, with the matrix scaled by 2^62. Each step at most doubles |u| + |v| and |q| + |r|, so the matrix of k ≤ 30 steps fits u·2^32 + v and q·2^32 + r in a word each, and the word arithmetic acts on both entries at once. The batch runs in two or three such parts, whose matrices multiply into that of the whole.
	private static long Divsteps(long zeta, ulong f, ulong g, out Transition t)
	{
		int parts = (BatchSteps + 29) / 30;
		zeta = PartDivsteps(zeta, ref f, ref g, BatchSteps / parts, out ulong uv, out ulong qr);
		Unpack(uv, out long u, out long v);
		Unpack(qr, out long q, out long r);
		// After k steps the low 62 − k bits of f and g are still right, as many as the steps left need.
		zeta = PartDivsteps(zeta, ref f, ref g, (BatchSteps + 1) / parts, out uv, out qr);
		Append(uv, qr, ref u, ref v, ref q, ref r);

		if (parts > 2)
		{
			zeta = PartDivsteps(zeta, ref f, ref g, (BatchSteps + 2) / parts, out uv, out qr);
			Append(uv, qr, ref u, ref v, ref q, ref r);
		}

		int scale = 62 - BatchSteps;
		t = new Transition(u << scale, v << scale, q << scale, r << scale);
		return zeta;
	}

	// Multiplies the matrix of the steps so far by that of the next part, packed in uv and qr. The product is the matrix of all those steps, so its entries stay within 2^62.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Append(ulong uv, ulong qr, ref long u, ref long v, ref long q, ref long r)
	{
		Unpack(uv, out long nextU, out long nextV);
		Unpack(qr, out long nextQ, out long nextR);
		(u, v, q, r) = (nextU * u + nextV * q, nextU * v + nextV * r, nextQ * u + nextR * q, nextQ * v + nextR * r);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static long PartDivsteps(long zeta, ref ulong fValue, ref ulong gValue, int steps, out ulong uvValue, out ulong qrValue)
	{
		ulong f = fValue;
		ulong g = gValue;
		ulong uv = 1UL << 32;
		ulong qr = 1;
		ulong odd = 0 - (g & 1);

		for (int i = 0; i < steps; ++i)
		{
			// ζ < 0 is δ > 0: then an odd g takes g − f and swaps.
			ulong negate = (ulong)(zeta >> 63);
			ulong swap = negate & odd;
			// On a swap, f takes the old g and u and v the old q and r, which adding the new g = g − f and q and r to them would give, without waiting for those.
			ulong fNext = f ^ (f ^ g) & swap;
			ulong uvNext = uv ^ (uv ^ qr) & swap;
			g += (f ^ negate) - negate & odd;
			qr += (uv ^ negate) - negate & odd;
			// ζ − 1 for 1 + δ, and ~ζ − 1 = −ζ − 2 for 1 − δ.
			zeta = (zeta ^ (long)swap) - 1;
			f = fNext;
			uv = uvNext << 1;
			// The parity of the next g is bit 1 of the sum, ahead of the shift.
			odd = (ulong)((long)(g << 62) >> 63);
			g >>= 1;
		}

		fValue = f;
		gValue = g;
		uvValue = uv;
		qrValue = qr;
		return zeta;
	}

	// Splits high·2^32 + low for |low| < 2^31.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Unpack(ulong packed, out long high, out long low)
	{
		low = (int)packed;
		high = (long)(packed - (ulong)low) >> 32;
	}

	// Runs 62 steps on the low limbs f and g and returns η after them. A run of even g is one shift, and while δ ≤ 0 an odd g only gains f, so a multiple of f clears several of its low bits at once, up to the step at which δ turns positive.
	private static long DivstepsVariableTime(long eta, ulong f, ulong g, out Transition t)
	{
		ulong u = 1;
		ulong v = 0;
		ulong q = 0;
		ulong r = 1;
		int left = 62;

		while (true)
		{
			// The bit at left caps the run at the steps left.
			int zeros = BitOperations.TrailingZeroCount(g | ulong.MaxValue << left);
			g >>= zeros;
			u <<= zeros;
			v <<= zeros;
			eta -= zeros;
			left -= zeros;

			if (left is 0)
			{
				break;
			}

			int limit;
			ulong w;

			// For δ > 0 the step goes to (g, g − f), which is (g, −f) and then the addition below.
			if (eta < 0)
			{
				eta = -eta;
				(f, g) = (g, 0 - f);
				(u, q) = (q, 0 - u);
				(v, r) = (r, 0 - v);
				limit = Math.Min((int)eta + 1, left);
				// w = −g/f modulo 2^6, as f·(f² − 2) ≡ −1/f.
				w = f * g * (f * f - 2) & ulong.MaxValue >> 64 - limit & 63;
			}
			else
			{
				limit = Math.Min((int)eta + 1, left);
				// w = −g/f modulo 2^4, as f + 8·((f + 1)/4 mod 2) ≡ 1/f.
				w = 0 - (f + ((f + 1 & 4) << 1)) * g & ulong.MaxValue >> 64 - limit & 15;
			}

			g += f * w;
			q += u * w;
			r += v * w;
		}

		t = new Transition((long)u, (long)v, (long)q, (long)r);
		return eta;
	}

	// Replaces the first length limbs of f and g with t·(f, g)/2^62. The batch makes the low 62 bits of u·f + v·g and q·f + r·g 0, so every limb of the result is the accumulated column above it.
	private static void UpdateFG(ref long f, ref long g, in Transition t, int length)
	{
		ulong u = (ulong)t.U;
		ulong v = (ulong)t.V;
		ulong q = (ulong)t.Q;
		ulong r = (ulong)t.R;
		Sum fSum = default;
		Sum gSum = default;
		int last = length - 1;

		if (last > 0)
		{
			ulong f0 = (ulong)f;
			ulong g0 = (ulong)g;
			MultiplyAdd(ref fSum, u, f0, 0);
			MultiplyAdd(ref fSum, v, g0, 0);
			MultiplyAdd(ref gSum, q, f0, 0);
			MultiplyAdd(ref gSum, r, g0, 0);
			_ = ShiftRight62(ref fSum);
			_ = ShiftRight62(ref gSum);
		}

		if (last > 1)
		{
			AddColumn(ref f, ref g, 1, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 2)
		{
			AddColumn(ref f, ref g, 2, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 3)
		{
			AddColumn(ref f, ref g, 3, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 4)
		{
			AddColumn(ref f, ref g, 4, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 5)
		{
			AddColumn(ref f, ref g, 5, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 6)
		{
			AddColumn(ref f, ref g, 6, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 7)
		{
			AddColumn(ref f, ref g, 7, u, v, q, r, ref fSum, ref gSum);
		}

		if (last > 8)
		{
			AddColumn(ref f, ref g, 8, u, v, q, r, ref fSum, ref gSum);
		}

		ulong fTop = (ulong)Unsafe.Add(ref f, last);
		ulong gTop = (ulong)Unsafe.Add(ref g, last);
		ulong fTopSign = (ulong)((long)fTop >> 63);
		ulong gTopSign = (ulong)((long)gTop >> 63);
		MultiplyAdd(ref fSum, u, fTop, fTopSign);
		MultiplyAdd(ref fSum, v, gTop, gTopSign);
		MultiplyAdd(ref gSum, q, fTop, fTopSign);
		MultiplyAdd(ref gSum, r, gTop, gTopSign);
		ulong fBelow = ShiftRight62(ref fSum);
		ulong gBelow = ShiftRight62(ref gSum);

		if (last > 0)
		{
			Unsafe.Add(ref f, last - 1) = (long)fBelow;
			Unsafe.Add(ref g, last - 1) = (long)gBelow;
		}

		Unsafe.Add(ref f, last) = (long)fSum.Low;
		Unsafe.Add(ref g, last) = (long)gSum.Low;
	}

	// Adds column i of t·(f, g), below the top, and writes the finished limb i − 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddColumn(ref long f, ref long g, int i, ulong u, ulong v, ulong q, ulong r, ref Sum fSum, ref Sum gSum)
	{
		ulong fLimb = (ulong)Unsafe.Add(ref f, i);
		ulong gLimb = (ulong)Unsafe.Add(ref g, i);
		MultiplyAdd(ref fSum, u, fLimb, 0);
		MultiplyAdd(ref fSum, v, gLimb, 0);
		MultiplyAdd(ref gSum, q, fLimb, 0);
		MultiplyAdd(ref gSum, r, gLimb, 0);
		Unsafe.Add(ref f, i - 1) = (long)ShiftRight62(ref fSum);
		Unsafe.Add(ref g, i - 1) = (long)ShiftRight62(ref gSum);
	}

	// Replaces d and e with t·(d, e)/2^62 modulo m. For d and e in (−2m, m), adding m to those below 0 brings them to (−m, m), and t·(d, e) to (−2^62·m, 2^62·m); the multiple of m below 2^62 that clears the low 62 bits then leaves (−2m, m) after the division. md and me gather both multiples.
	private static void UpdateDE(ref State state, in Transition t)
	{
		ref long d = ref state.D[0];
		ref long e = ref state.E[0];
		ref long m = ref state.M[0];
		int last = Length - 1;
		ulong u = (ulong)t.U;
		ulong v = (ulong)t.V;
		ulong q = (ulong)t.Q;
		ulong r = (ulong)t.R;
		ulong dSign = (ulong)(Unsafe.Add(ref d, last) >> 63);
		ulong eSign = (ulong)(Unsafe.Add(ref e, last) >> 63);
		ulong md = (u & dSign) + (v & eSign);
		ulong me = (q & dSign) + (r & eSign);
		Sum dSum = default;
		Sum eSum = default;
		ulong d0 = (ulong)d;
		ulong e0 = (ulong)e;
		MultiplyAdd(ref dSum, u, d0, 0);
		MultiplyAdd(ref dSum, v, e0, 0);
		MultiplyAdd(ref eSum, q, d0, 0);
		MultiplyAdd(ref eSum, r, e0, 0);
		// m⁻¹ modulo 2^64 is −NegativeInverse. Lowering md by (m⁻¹·low + md) mod 2^62 clears the low 62 bits of the sum once md·m is in; a decrease below 2^62, rather than a new md, is what the range above needs, and it keeps md within (−2^63, 2^62].
		ulong inverse = 0 - TModulus.NegativeInverse;
		md -= inverse * dSum.Low + md & LimbMask;
		me -= inverse * eSum.Low + me & LimbMask;
		ulong m0 = (ulong)m;
		MultiplyAdd(ref dSum, md, m0, 0);
		MultiplyAdd(ref eSum, me, m0, 0);

		Debug.Assert((dSum.Low & LimbMask) is 0 && (eSum.Low & LimbMask) is 0);

		_ = ShiftRight62(ref dSum);
		_ = ShiftRight62(ref eSum);

		if (last > 1)
		{
			AddColumn(ref d, ref e, ref m, 1, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 2)
		{
			AddColumn(ref d, ref e, ref m, 2, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 3)
		{
			AddColumn(ref d, ref e, ref m, 3, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 4)
		{
			AddColumn(ref d, ref e, ref m, 4, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 5)
		{
			AddColumn(ref d, ref e, ref m, 5, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 6)
		{
			AddColumn(ref d, ref e, ref m, 6, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 7)
		{
			AddColumn(ref d, ref e, ref m, 7, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		if (last > 8)
		{
			AddColumn(ref d, ref e, ref m, 8, u, v, q, r, md, me, ref dSum, ref eSum);
		}

		ulong dTop = (ulong)Unsafe.Add(ref d, last);
		ulong eTop = (ulong)Unsafe.Add(ref e, last);
		ulong mTop = (ulong)Unsafe.Add(ref m, last);
		MultiplyAdd(ref dSum, u, dTop, dSign);
		MultiplyAdd(ref dSum, v, eTop, eSign);
		MultiplyAdd(ref dSum, md, mTop, 0);
		MultiplyAdd(ref eSum, q, dTop, dSign);
		MultiplyAdd(ref eSum, r, eTop, eSign);
		MultiplyAdd(ref eSum, me, mTop, 0);
		Unsafe.Add(ref d, last - 1) = (long)ShiftRight62(ref dSum);
		Unsafe.Add(ref e, last - 1) = (long)ShiftRight62(ref eSum);
		Unsafe.Add(ref d, last) = (long)dSum.Low;
		Unsafe.Add(ref e, last) = (long)eSum.Low;
	}

	// Adds column i of t·(d, e) and the multiples of m, below the top, and writes the finished limb i − 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddColumn(ref long d, ref long e, ref long m, int i, ulong u, ulong v, ulong q, ulong r, ulong md, ulong me, ref Sum dSum, ref Sum eSum)
	{
		ulong dLimb = (ulong)Unsafe.Add(ref d, i);
		ulong eLimb = (ulong)Unsafe.Add(ref e, i);
		ulong mLimb = (ulong)Unsafe.Add(ref m, i);
		MultiplyAdd(ref dSum, u, dLimb, 0);
		MultiplyAdd(ref dSum, v, eLimb, 0);
		MultiplyAdd(ref dSum, md, mLimb, 0);
		MultiplyAdd(ref eSum, q, dLimb, 0);
		MultiplyAdd(ref eSum, r, eLimb, 0);
		MultiplyAdd(ref eSum, me, mLimb, 0);
		Unsafe.Add(ref d, i - 1) = (long)ShiftRight62(ref dSum);
		Unsafe.Add(ref e, i - 1) = (long)ShiftRight62(ref eSum);
	}

	// d is in (−2m, m) and fTop, the top limb of f = ±1, has its sign. Sets result to d·f modulo m.
	private static void Store(ref State state, long fTop, out FieldElement<TModulus> result)
	{
		ref long d = ref state.D[0];
		ref long m = ref state.M[0];
		int last = Length - 1;
		// Adding m below 0 brings d to (−m, m), which the negation keeps; another m below 0 then brings it to [0, m).
		long add = Unsafe.Add(ref d, last) >> 63;
		long negate = fTop >> 63;

		for (int i = 0; i <= last; ++i)
		{
			ref long limb = ref Unsafe.Add(ref d, i);
			limb = (limb + (Unsafe.Add(ref m, i) & add) ^ negate) - negate;
		}

		Normalize(ref d);
		add = Unsafe.Add(ref d, last) >> 63;

		for (int i = 0; i <= last; ++i)
		{
			Unsafe.Add(ref d, i) += Unsafe.Add(ref m, i) & add;
		}

		Normalize(ref d);
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<TModulus>, ulong>(ref result);

		// Limb j holds bits 64j to 64j + 63, which start 2j bits into limb j of d for j < 31.
		for (int j = 0; j < TModulus.LimbCount; ++j)
		{
			ulong above = j + 1 < Length ? (ulong)Unsafe.Add(ref d, j + 1) : 0;
			Unsafe.Add(ref limbs, j) = (ulong)Unsafe.Add(ref d, j) >> 2 * j | above << 62 - 2 * j;
		}
	}

	// Carries the bits above 62 of every limb but the top one into the next, leaving them in [0, 2^62).
	private static void Normalize(ref long limbs)
	{
		for (int i = 0; i < Length - 1; ++i)
		{
			ref long limb = ref Unsafe.Add(ref limbs, i);
			Unsafe.Add(ref limb, 1) += limb >> 62;
			limb &= (long)LimbMask;
		}
	}

	private static bool IsZero(ref long limbs, int length)
	{
		long bits = 0;

		for (int i = 0; i < length; ++i)
		{
			bits |= Unsafe.Add(ref limbs, i);
		}

		return bits is 0;
	}

	// sum gains x·y, for x of either sign and y either below 2^62 or a top limb whose sign mask is ySign.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyAdd(ref Sum sum, ulong x, ulong y, ulong ySign)
	{
		// The product of x and y as unsigned words exceeds the signed one by 2^64·y if x < 0 and by 2^64·x if y < 0.
		ulong productHigh = MultiplyOutOfLine(x, y, out ulong productLow) - (y & (ulong)((long)x >> 63)) - (x & ySign);
		sum.Low += productLow;
		sum.High += productHigh + Carry(sum.Low, productLow);
	}

	// Returns the low 62 bits of sum and divides it by 2^62.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ShiftRight62(ref Sum sum)
	{
		ulong limb = sum.Low & LimbMask;
		sum.Low = sum.Low >> 62 | sum.High << 2;
		sum.High = (ulong)((long)sum.High >> 62);
		return limb;
	}

	// f' = (u·f + v·g)/2^62 and g' = (q·f + r·g)/2^62.
	private readonly struct Transition(long u, long v, long q, long r)
	{
		internal readonly long U = u;
		internal readonly long V = v;
		internal readonly long Q = q;
		internal readonly long R = r;
	}

	// A signed 128-bit column sum, Low + 2^64·High.
	private struct Sum
	{
		internal ulong Low;
		internal ulong High;
	}

	private struct State
	{
		internal Limbs F;
		internal Limbs G;
		internal Limbs D;
		internal Limbs E;
		internal Limbs M;
	}

	[InlineArray(Capacity)]
	private struct Limbs
	{
		private long _limb;
	}
}
